#include "audit_view.h"

#include <gui/canvas.h>
#include <furi.h>
#include <koi_core/koi_trit.h>
#include <koi_core/koi_audit.h>
#include <stdio.h>

#define AUDIT_VIEW_PAGE_SIZE 4

typedef struct {
    KoiCore* core;
    uint8_t  scroll;
} AuditViewModel;

static const char* DOMAIN_SHORT[KOI_DOMAIN_COUNT] = {
    "RF", "BT", "VT", "MX", "AP",
};

static void audit_view_draw(Canvas* canvas, void* model_ptr) {
    AuditViewModel* m = model_ptr;
    const KoiAudit* audit = koi_core_get_audit(m->core);
    uint8_t count = koi_audit_count(audit);

    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 10, "Audit Log (newest first)");
    canvas_draw_line(canvas, 0, 12, 128, 12);

    if(count == 0) {
        canvas_draw_str(canvas, 20, 36, "No decisions yet.");
        return;
    }

    for(uint8_t i = 0; i < AUDIT_VIEW_PAGE_SIZE; i++) {
        uint8_t idx = m->scroll + i;
        if(idx >= count) break;

        const AuditEntry* e = koi_audit_get(audit, idx);
        char row[48];
        snprintf(row, sizeof(row), "#%03d %s %s t=%lu",
            (int)idx,
            DOMAIN_SHORT[e->domain < KOI_DOMAIN_COUNT ? e->domain : 0],
            e->result > 0 ? "ALW" : e->result < 0 ? "DEN" : "NEU",
            (unsigned long)e->tick);
        canvas_draw_str(canvas, 2, (uint8_t)(24 + i * 12), row);
    }

    if(m->scroll > 0)
        canvas_draw_str(canvas, 120, 20, "^");
    if(m->scroll + AUDIT_VIEW_PAGE_SIZE < count)
        canvas_draw_str(canvas, 120, 60, "v");
}

static bool audit_view_input(InputEvent* event, void* model_ptr) {
    AuditViewModel* m = model_ptr;
    const KoiAudit* audit = koi_core_get_audit(m->core);
    uint8_t count = koi_audit_count(audit);

    if(event->type == InputTypePress || event->type == InputTypeRepeat) {
        if(event->key == InputKeyUp && m->scroll > 0) {
            m->scroll--;
            return true;
        }
        if(event->key == InputKeyDown && m->scroll + AUDIT_VIEW_PAGE_SIZE < count) {
            m->scroll++;
            return true;
        }
    }
    return false;
}

static void audit_view_enter(void* model_ptr) {
    AuditViewModel* m = model_ptr;
    m->scroll = 0;
}

View* koi_audit_view_alloc(KoiCore* core) {
    View* view = view_alloc();
    view_set_draw_callback(view, audit_view_draw);
    view_set_input_callback(view, audit_view_input);
    view_set_enter_callback(view, audit_view_enter);
    view_allocate_model(view, ViewModelTypeLocking, sizeof(AuditViewModel));

    AuditViewModel* m = view_get_model(view);
    m->core   = core;
    m->scroll = 0;
    view_commit_model(view, false);

    return view;
}

void koi_audit_view_free(View* view) {
    view_free(view);
}
