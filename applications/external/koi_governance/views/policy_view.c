#include "policy_view.h"

#include <gui/canvas.h>
#include <furi.h>
#include <services/koi_core/koi_trit.h>
#include <stdio.h>

typedef struct {
    KoiCore* core;
    uint8_t  domain;
    uint8_t  scroll;
} PolicyViewModel;

static const char* DOMAIN_NAMES[KOI_DOMAIN_COUNT] = {
    "RF", "BLE", "Vault", "Mesh", "App",
};

static void policy_view_draw(Canvas* canvas, void* model_ptr) {
    PolicyViewModel* m = model_ptr;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);

    char header[32];
    snprintf(header, sizeof(header), "< %s Rules >", DOMAIN_NAMES[m->domain]);
    canvas_draw_str(canvas, 2, 10, header);
    canvas_draw_line(canvas, 0, 12, 128, 12);

    trit_t decision = koi_core_evaluate(m->core, m->domain);
    char dec_str[24];
    snprintf(dec_str, sizeof(dec_str), "Decision: %s",
        decision > 0 ? "ALLOW" : decision < 0 ? "DENY" : "NEUT");
    canvas_draw_str(canvas, 2, 23, dec_str);

    canvas_draw_str(canvas, 2, 63, "L/R:domain");
}

static bool policy_view_input(InputEvent* event, void* model_ptr) {
    PolicyViewModel* m = model_ptr;
    if(event->type == InputTypePress || event->type == InputTypeRepeat) {
        if(event->key == InputKeyLeft) {
            m->domain = (uint8_t)((m->domain + KOI_DOMAIN_COUNT - 1) % KOI_DOMAIN_COUNT);
            m->scroll = 0;
            return true;
        }
        if(event->key == InputKeyRight) {
            m->domain = (uint8_t)((m->domain + 1) % KOI_DOMAIN_COUNT);
            m->scroll = 0;
            return true;
        }
    }
    return false;
}

static void policy_view_enter(void* model_ptr) {
    PolicyViewModel* m = model_ptr;
    m->domain = KOI_DOMAIN_RF;
    m->scroll = 0;
}

View* koi_policy_view_alloc(KoiCore* core) {
    View* view = view_alloc();
    view_set_draw_callback(view, policy_view_draw);
    view_set_input_callback(view, policy_view_input);
    view_set_enter_callback(view, policy_view_enter);
    view_allocate_model(view, ViewModelTypeLocking, sizeof(PolicyViewModel));

    PolicyViewModel* m = view_get_model(view);
    m->core   = core;
    m->domain = KOI_DOMAIN_RF;
    m->scroll = 0;
    view_commit_model(view, false);

    return view;
}

void koi_policy_view_free(View* view) {
    view_free(view);
}
