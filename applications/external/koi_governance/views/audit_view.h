#pragma once

#include <gui/view.h>
#include <koi_core/koi_core.h>

View* koi_audit_view_alloc(KoiCoreApi* api);
void  koi_audit_view_free(View* view);
