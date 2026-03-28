// applications/external/koi_vault/views/pin_view.h
#pragma once

#include <gui/view.h>

/** Callback when PIN entry is confirmed. */
typedef void (*PinViewCallback)(const char* pin, void* context);

/** Allocate the PIN entry view. */
View* koi_pin_view_alloc(void);

/** Free the PIN entry view. */
void koi_pin_view_free(View* view);

/** Set callback for when PIN is submitted. */
void koi_pin_view_set_callback(View* view, PinViewCallback callback, void* context);

/** Set the header text (e.g. "Enter PIN", "Create PIN", "Duress PIN"). */
void koi_pin_view_set_header(View* view, const char* header);

/** Reset the view (clear entered digits). */
void koi_pin_view_reset(View* view);
