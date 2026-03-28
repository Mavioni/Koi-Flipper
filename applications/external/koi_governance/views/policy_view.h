#pragma once

#include <gui/view.h>
#include <services/koi_core/koi_core.h>

View* koi_policy_view_alloc(KoiCore* core);
void  koi_policy_view_free(View* view);
