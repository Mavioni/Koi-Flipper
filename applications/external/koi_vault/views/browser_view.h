// applications/external/koi_vault/views/browser_view.h
#pragma once

#include <gui/view.h>
#include "../koi_vault.h"

typedef enum {
    BrowserActionNone = 0,
    BrowserActionView,     // User wants to view selected file
    BrowserActionAdd,      // User wants to add a new file
    BrowserActionDelete,   // User wants to delete selected file
} BrowserAction;

typedef void (*BrowserViewCallback)(BrowserAction action, uint16_t selected_index, void* context);

View* koi_browser_view_alloc(KoiVault* vault);
void  koi_browser_view_free(View* view);
void  koi_browser_view_set_callback(View* view, BrowserViewCallback callback, void* context);
void  koi_browser_view_refresh(View* view);
