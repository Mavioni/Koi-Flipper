#pragma once

#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>

#include <services/koi_core/koi_core.h>
#include <services/koi_core/koi_audit.h>

typedef enum {
    KoiGovernanceViewMenu   = 0,
    KoiGovernanceViewState  = 1,
    KoiGovernanceViewPolicy = 2,
    KoiGovernanceViewAudit  = 3,
} KoiGovernanceViewId;

typedef struct {
    Gui*            gui;
    ViewDispatcher* view_dispatcher;
    Submenu*        menu;

    View* state_view;
    View* policy_view;
    View* audit_view;

    KoiCore* koi_core;
} KoiGovernanceApp;
