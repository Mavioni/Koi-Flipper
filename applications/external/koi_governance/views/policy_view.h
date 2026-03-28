#pragma once

#include <gui/view.h>
#include <koi_core/koi_core.h>

View* koi_policy_view_alloc(KoiCoreApi* api);
void  koi_policy_view_free(View* view);
