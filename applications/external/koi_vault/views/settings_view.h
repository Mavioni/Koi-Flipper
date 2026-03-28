// applications/external/koi_vault/views/settings_view.h
#pragma once

#include <gui/view.h>
#include "../koi_vault.h"

typedef enum {
    SettingsActionCreateVault  = 0,
    SettingsActionChangePIN    = 1,
    SettingsActionSetDuress    = 2,
    SettingsActionLockVault    = 3,
} SettingsAction;

typedef void (*SettingsViewCallback)(SettingsAction action, void* context);

View* koi_settings_view_alloc(KoiVault* vault);
void  koi_settings_view_free(View* view);
void  koi_settings_view_set_callback(View* view, SettingsViewCallback callback, void* context);
