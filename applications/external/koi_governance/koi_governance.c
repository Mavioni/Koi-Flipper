#include "koi_governance_app.h"
#include "views/state_view.h"
#include "views/policy_view.h"
#include "views/audit_view.h"

#include <furi.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>

// ---------------------------------------------------------------------------
// Menu callbacks
// ---------------------------------------------------------------------------

static void menu_callback(void* context, uint32_t index) {
    KoiGovernanceApp* app = context;
    view_dispatcher_switch_to_view(app->view_dispatcher, (uint32_t)index + 1);
}

static uint32_t back_to_menu(void* context) {
    UNUSED(context);
    return KoiGovernanceViewMenu;
}

static uint32_t back_to_exit(void* context) {
    UNUSED(context);
    return VIEW_NONE;
}

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------

static KoiGovernanceApp* koi_governance_alloc(void) {
    KoiGovernanceApp* app = malloc(sizeof(KoiGovernanceApp));
    furi_check(app != NULL);

    app->koi_core = furi_record_open(RECORD_KOI_CORE);
    app->gui = furi_record_open(RECORD_GUI);

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_enable_queue(app->view_dispatcher);
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    // Menu
    app->menu = submenu_alloc();
    submenu_add_item(app->menu, "State",     KoiGovernanceViewState  - 1, menu_callback, app);
    submenu_add_item(app->menu, "Policies",  KoiGovernanceViewPolicy - 1, menu_callback, app);
    submenu_add_item(app->menu, "Audit Log", KoiGovernanceViewAudit  - 1, menu_callback, app);

    View* menu_view = submenu_get_view(app->menu);
    view_set_previous_callback(menu_view, back_to_exit);
    view_dispatcher_add_view(app->view_dispatcher, KoiGovernanceViewMenu, menu_view);

    // Content views
    app->state_view  = koi_state_view_alloc(app->koi_core);
    app->policy_view = koi_policy_view_alloc(app->koi_core);
    app->audit_view  = koi_audit_view_alloc(app->koi_core);

    view_set_previous_callback(app->state_view,  back_to_menu);
    view_set_previous_callback(app->policy_view, back_to_menu);
    view_set_previous_callback(app->audit_view,  back_to_menu);

    view_dispatcher_add_view(app->view_dispatcher, KoiGovernanceViewState,  app->state_view);
    view_dispatcher_add_view(app->view_dispatcher, KoiGovernanceViewPolicy, app->policy_view);
    view_dispatcher_add_view(app->view_dispatcher, KoiGovernanceViewAudit,  app->audit_view);

    return app;
}

static void koi_governance_free(KoiGovernanceApp* app) {
    view_dispatcher_remove_view(app->view_dispatcher, KoiGovernanceViewMenu);
    view_dispatcher_remove_view(app->view_dispatcher, KoiGovernanceViewState);
    view_dispatcher_remove_view(app->view_dispatcher, KoiGovernanceViewPolicy);
    view_dispatcher_remove_view(app->view_dispatcher, KoiGovernanceViewAudit);

    koi_state_view_free(app->state_view);
    koi_policy_view_free(app->policy_view);
    koi_audit_view_free(app->audit_view);

    submenu_free(app->menu);
    view_dispatcher_free(app->view_dispatcher);

    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_KOI_CORE);
    free(app);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int32_t koi_governance_app(void* p) {
    UNUSED(p);
    KoiGovernanceApp* app = koi_governance_alloc();
    view_dispatcher_switch_to_view(app->view_dispatcher, KoiGovernanceViewMenu);
    view_dispatcher_run(app->view_dispatcher);
    koi_governance_free(app);
    return 0;
}
