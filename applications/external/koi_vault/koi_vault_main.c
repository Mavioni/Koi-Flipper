// applications/external/koi_vault/koi_vault_main.c
#include "koi_vault_app.h"
#include "views/pin_view.h"
#include "views/browser_view.h"
#include "views/settings_view.h"

#include <furi.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <string.h>

#define TAG "KoiVaultApp"

// ---------------------------------------------------------------------------
// Navigation callbacks
// ---------------------------------------------------------------------------

static uint32_t back_to_menu(void* context) {
    UNUSED(context);
    return KoiVaultViewMenu;
}

static uint32_t back_to_exit(void* context) {
    UNUSED(context);
    return VIEW_NONE;
}

// ---------------------------------------------------------------------------
// PIN callbacks
// ---------------------------------------------------------------------------

static void pin_callback(const char* pin, void* context) {
    KoiVaultApp* app = context;

    switch(app->pin_mode) {
    case 0: { // Open vault
        KoiVaultState result = koi_vault_open(app->vault, pin);
        if(result == KoiVaultStateUnlocked || result == KoiVaultStateDuress) {
            koi_browser_view_refresh(app->browser_view);
            view_dispatcher_switch_to_view(app->view_dispatcher, KoiVaultViewBrowser);
        } else if(result == KoiVaultStateLockout) {
            koi_pin_view_set_header(app->pin_view, "LOCKED OUT!");
            koi_pin_view_reset(app->pin_view);
        } else {
            char header[32];
            snprintf(header, sizeof(header), "Wrong PIN (%d/%d)",
                app->vault->pin_attempts, KOI_VAULT_MAX_PIN_ATTEMPTS);
            koi_pin_view_set_header(app->pin_view, header);
            koi_pin_view_reset(app->pin_view);
        }
        break;
    }
    case 1: { // Create vault — first PIN entry
        strncpy(app->pending_pin, pin, 32);
        app->pin_mode = 10; // confirm step
        koi_pin_view_set_header(app->pin_view, "Confirm PIN");
        koi_pin_view_reset(app->pin_view);
        break;
    }
    case 10: { // Create vault — confirm PIN
        if(strcmp(app->pending_pin, pin) == 0) {
            if(koi_vault_create(app->vault, pin, NULL)) {
                FURI_LOG_I(TAG, "Vault created!");
                view_dispatcher_switch_to_view(app->view_dispatcher, KoiVaultViewMenu);
            }
        } else {
            koi_pin_view_set_header(app->pin_view, "Mismatch! Retry");
            koi_pin_view_reset(app->pin_view);
            app->pin_mode = 1;
        }
        memset(app->pending_pin, 0, sizeof(app->pending_pin));
        break;
    }
    case 2: { // Change PIN
        if(koi_vault_change_pin(app->vault, pin)) {
            view_dispatcher_switch_to_view(app->view_dispatcher, KoiVaultViewSettings);
        }
        break;
    }
    case 3: { // Set duress PIN
        if(koi_vault_set_duress_pin(app->vault, pin)) {
            view_dispatcher_switch_to_view(app->view_dispatcher, KoiVaultViewSettings);
        }
        break;
    }
    }
}

// ---------------------------------------------------------------------------
// Browser callbacks
// ---------------------------------------------------------------------------

static void browser_callback(BrowserAction action, uint16_t index, void* context) {
    KoiVaultApp* app = context;
    UNUSED(index);

    switch(action) {
    case BrowserActionView:
        // TODO: file viewer sub-view (Phase 3.5)
        break;
    case BrowserActionAdd:
        // TODO: file import sub-view (Phase 3.5)
        break;
    case BrowserActionDelete: {
        const KoiVaultIndexEntry* entry = koi_vault_file_get(app->vault, index);
        if(entry) {
            koi_vault_file_delete(app->vault, entry->name);
            koi_browser_view_refresh(app->browser_view);
        }
        break;
    }
    default:
        break;
    }
}

// ---------------------------------------------------------------------------
// Settings callbacks
// ---------------------------------------------------------------------------

static void settings_callback(SettingsAction action, void* context) {
    KoiVaultApp* app = context;

    switch(action) {
    case SettingsActionCreateVault:
        app->pin_mode = 1;
        koi_pin_view_set_header(app->pin_view, "Create PIN");
        koi_pin_view_reset(app->pin_view);
        view_dispatcher_switch_to_view(app->view_dispatcher, KoiVaultViewPin);
        break;

    case SettingsActionChangePIN:
        app->pin_mode = 2;
        koi_pin_view_set_header(app->pin_view, "New PIN");
        koi_pin_view_reset(app->pin_view);
        view_dispatcher_switch_to_view(app->view_dispatcher, KoiVaultViewPin);
        break;

    case SettingsActionSetDuress:
        app->pin_mode = 3;
        koi_pin_view_set_header(app->pin_view, "Duress PIN");
        koi_pin_view_reset(app->pin_view);
        view_dispatcher_switch_to_view(app->view_dispatcher, KoiVaultViewPin);
        break;

    case SettingsActionLockVault:
        koi_vault_lock(app->vault);
        view_dispatcher_switch_to_view(app->view_dispatcher, KoiVaultViewMenu);
        break;
    }
}

// ---------------------------------------------------------------------------
// Menu callback
// ---------------------------------------------------------------------------

static void menu_callback(void* context, uint32_t index) {
    KoiVaultApp* app = context;

    switch(index) {
    case 0: // Open/Unlock
        if(app->vault->state == KoiVaultStateLocked) {
            app->pin_mode = 0;
            koi_pin_view_set_header(app->pin_view, "Enter PIN");
            koi_pin_view_reset(app->pin_view);
            view_dispatcher_switch_to_view(app->view_dispatcher, KoiVaultViewPin);
        } else if(app->vault->state == KoiVaultStateUnlocked ||
                  app->vault->state == KoiVaultStateDuress) {
            koi_browser_view_refresh(app->browser_view);
            view_dispatcher_switch_to_view(app->view_dispatcher, KoiVaultViewBrowser);
        }
        break;
    case 1: // Settings
        view_dispatcher_switch_to_view(app->view_dispatcher, KoiVaultViewSettings);
        break;
    }
}

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------

static KoiVaultApp* koi_vault_app_alloc(void) {
    KoiVaultApp* app = malloc(sizeof(KoiVaultApp));
    furi_check(app != NULL);
    memset(app, 0, sizeof(KoiVaultApp));

    app->vault = koi_vault_alloc();
    app->gui = furi_record_open(RECORD_GUI);

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_enable_queue(app->view_dispatcher);
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    // Menu
    app->menu = submenu_alloc();
    submenu_add_item(app->menu, "Open Vault",  0, menu_callback, app);
    submenu_add_item(app->menu, "Settings",     1, menu_callback, app);

    View* menu_view = submenu_get_view(app->menu);
    view_set_previous_callback(menu_view, back_to_exit);
    view_dispatcher_add_view(app->view_dispatcher, KoiVaultViewMenu, menu_view);

    // PIN view
    app->pin_view = koi_pin_view_alloc();
    koi_pin_view_set_callback(app->pin_view, pin_callback, app);
    view_set_previous_callback(app->pin_view, back_to_menu);
    view_dispatcher_add_view(app->view_dispatcher, KoiVaultViewPin, app->pin_view);

    // Browser view
    app->browser_view = koi_browser_view_alloc(app->vault);
    koi_browser_view_set_callback(app->browser_view, browser_callback, app);
    view_set_previous_callback(app->browser_view, back_to_menu);
    view_dispatcher_add_view(app->view_dispatcher, KoiVaultViewBrowser, app->browser_view);

    // Settings view
    app->settings_view = koi_settings_view_alloc(app->vault);
    koi_settings_view_set_callback(app->settings_view, settings_callback, app);
    view_set_previous_callback(app->settings_view, back_to_menu);
    view_dispatcher_add_view(app->view_dispatcher, KoiVaultViewSettings, app->settings_view);

    return app;
}

static void koi_vault_app_free(KoiVaultApp* app) {
    view_dispatcher_remove_view(app->view_dispatcher, KoiVaultViewMenu);
    view_dispatcher_remove_view(app->view_dispatcher, KoiVaultViewPin);
    view_dispatcher_remove_view(app->view_dispatcher, KoiVaultViewBrowser);
    view_dispatcher_remove_view(app->view_dispatcher, KoiVaultViewSettings);

    koi_pin_view_free(app->pin_view);
    koi_browser_view_free(app->browser_view);
    koi_settings_view_free(app->settings_view);

    submenu_free(app->menu);
    view_dispatcher_free(app->view_dispatcher);

    furi_record_close(RECORD_GUI);
    koi_vault_free(app->vault);

    memset(app->pending_pin, 0, sizeof(app->pending_pin));
    free(app);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int32_t koi_vault_app(void* p) {
    UNUSED(p);
    KoiVaultApp* app = koi_vault_app_alloc();
    view_dispatcher_switch_to_view(app->view_dispatcher, KoiVaultViewMenu);
    view_dispatcher_run(app->view_dispatcher);
    koi_vault_app_free(app);
    return 0;
}
