// applications/external/koi_vault/koi_vault_app.h
#pragma once

#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>

#include "koi_vault.h"

typedef enum {
    KoiVaultViewMenu     = 0,
    KoiVaultViewPin      = 1,
    KoiVaultViewBrowser  = 2,
    KoiVaultViewSettings = 3,
} KoiVaultViewId;

typedef struct {
    Gui*            gui;
    ViewDispatcher* view_dispatcher;
    Submenu*        menu;

    View* pin_view;
    View* browser_view;
    View* settings_view;

    KoiVault* vault;

    // Tracks what PIN entry is for (open, create, change, duress)
    uint8_t pin_mode; // 0=open, 1=create, 2=change, 3=duress
    char pending_pin[33]; // for two-step flows (create/change)
} KoiVaultApp;
