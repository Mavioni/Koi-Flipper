#pragma once

#include <gui/view.h>
#include <koi_core/koi_core.h>

/** Allocate and configure the state view. Caller owns the returned View*. */
View* koi_state_view_alloc(KoiCoreApi* api);

/** Free the state view and its model. */
void koi_state_view_free(View* view);
