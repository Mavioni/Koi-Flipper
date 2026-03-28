// applications/external/koi_vault/views/settings_view.c
#include "settings_view.h"

#include <gui/canvas.h>
#include <furi.h>
#include <string.h>

#define SETTINGS_ITEM_COUNT 4

typedef struct {
    KoiVault* vault;
    uint8_t   selected;
    SettingsViewCallback callback;
    void* callback_context;
} SettingsViewModel;

static const char* SETTINGS_ITEMS[SETTINGS_ITEM_COUNT] = {
    "Create Vault",
    "Change PIN",
    "Set Duress PIN",
    "Lock Vault",
};

static void settings_view_draw(Canvas* canvas, void* model_ptr) {
    SettingsViewModel* m = model_ptr;
    canvas_clear(canvas);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 10, "Vault Settings");
    canvas_draw_line(canvas, 0, 12, 128, 12);

    canvas_set_font(canvas, FontSecondary);

    // Show vault state
    const char* state_str = "???";
    switch(m->vault->state) {
    case KoiVaultStateUninitialized: state_str = "[No vault]"; break;
    case KoiVaultStateLocked:        state_str = "[Locked]"; break;
    case KoiVaultStateUnlocked:      state_str = "[Unlocked]"; break;
    case KoiVaultStateDuress:        state_str = "[Duress]"; break;
    case KoiVaultStateLockout:       state_str = "[Lockout]"; break;
    }
    canvas_draw_str(canvas, 80, 10, state_str);

    for(uint8_t i = 0; i < SETTINGS_ITEM_COUNT; i++) {
        uint8_t y = (uint8_t)(24 + i * 12);
        bool is_selected = (i == m->selected);

        // Gray out items that don't apply in current state
        bool enabled = true;
        if(i == 0 && m->vault->state != KoiVaultStateUninitialized) enabled = false; // Create
        if(i == 1 && m->vault->state != KoiVaultStateUnlocked) enabled = false; // Change PIN
        if(i == 2 && m->vault->state != KoiVaultStateUnlocked) enabled = false; // Duress PIN
        if(i == 3 && m->vault->state != KoiVaultStateUnlocked &&
                     m->vault->state != KoiVaultStateDuress) enabled = false; // Lock

        if(is_selected) {
            canvas_draw_box(canvas, 0, (int16_t)(y - 9), 128, 12);
            canvas_set_color(canvas, ColorWhite);
        }

        if(!enabled) {
            // Draw with dashed style indicator
            char label[36];
            snprintf(label, sizeof(label), "  %s", SETTINGS_ITEMS[i]);
            canvas_draw_str(canvas, 2, y, label);
        } else {
            char label[36];
            snprintf(label, sizeof(label), "> %s", SETTINGS_ITEMS[i]);
            canvas_draw_str(canvas, 2, y, label);
        }

        if(is_selected) canvas_set_color(canvas, ColorBlack);
    }
}

static bool settings_view_input(InputEvent* event, void* model_ptr) {
    SettingsViewModel* m = model_ptr;

    if(event->type != InputTypePress && event->type != InputTypeRepeat) return false;

    switch(event->key) {
    case InputKeyUp:
        if(m->selected > 0) m->selected--;
        return true;
    case InputKeyDown:
        if(m->selected < SETTINGS_ITEM_COUNT - 1) m->selected++;
        return true;
    case InputKeyOk:
        if(m->callback) {
            m->callback((SettingsAction)m->selected, m->callback_context);
        }
        return true;
    default:
        break;
    }
    return false;
}

static void settings_view_enter(void* model_ptr) {
    SettingsViewModel* m = model_ptr;
    m->selected = 0;
}

View* koi_settings_view_alloc(KoiVault* vault) {
    View* view = view_alloc();
    view_set_draw_callback(view, settings_view_draw);
    view_set_input_callback(view, settings_view_input);
    view_set_enter_callback(view, settings_view_enter);
    view_allocate_model(view, ViewModelTypeLocking, sizeof(SettingsViewModel));

    SettingsViewModel* m = view_get_model(view);
    m->vault = vault;
    m->selected = 0;
    view_commit_model(view, false);

    return view;
}

void koi_settings_view_free(View* view) {
    view_free(view);
}

void koi_settings_view_set_callback(View* view, SettingsViewCallback callback, void* context) {
    SettingsViewModel* m = view_get_model(view);
    m->callback = callback;
    m->callback_context = context;
    view_commit_model(view, false);
}
