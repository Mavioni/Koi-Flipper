#include "state_view.h"

#include <gui/elements.h>
#include <gui/canvas.h>
#include <furi.h>
#include <koi_core/koi_trit.h>

typedef struct {
    KoiCoreApi* api;
    koi_state_t state;
    uint8_t     scroll;
} StateViewModel;

static const char* FIELD_NAMES[KOI_STATE_FIELD_COUNT] = {
    "NetTrust", "Vault", "Radio", "AppPerm",
    "Infer", "Mesh", "DataCls", "Power", "Identity",
};

static const char* trit_str(trit_t t) {
    if(t < 0) return "-1";
    if(t > 0) return "+1";
    return " 0";
}

static void state_view_draw(Canvas* canvas, void* model_ptr) {
    StateViewModel* m = model_ptr;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);

    canvas_draw_str(canvas, 2, 10, "Koi State");
    canvas_draw_line(canvas, 0, 12, 128, 12);

    // Show 4 fields per screen; scroll to see all 9
    for(uint8_t i = 0; i < 4 && (m->scroll + i) < KOI_STATE_FIELD_COUNT; i++) {
        uint8_t field = m->scroll + i;
        trit_t  val   = ((const trit_t*)&m->state)[field];
        uint8_t y     = 24 + (uint8_t)(i * 12);
        canvas_draw_str(canvas, 4, y, FIELD_NAMES[field]);
        canvas_draw_str(canvas, 90, y, trit_str(val));
    }

    if(m->scroll > 0)
        canvas_draw_str(canvas, 120, 20, "^");
    if(m->scroll + 4 < KOI_STATE_FIELD_COUNT)
        canvas_draw_str(canvas, 120, 60, "v");
}

static bool state_view_input(InputEvent* event, void* model_ptr) {
    StateViewModel* m = model_ptr;
    if(event->type == InputTypePress || event->type == InputTypeRepeat) {
        if(event->key == InputKeyUp && m->scroll > 0) {
            m->scroll--;
            return true;
        }
        if(event->key == InputKeyDown && m->scroll + 4 < KOI_STATE_FIELD_COUNT) {
            m->scroll++;
            return true;
        }
        if(event->key == InputKeyOk) {
            m->state = m->api->get_state(m->api);
            return true;
        }
    }
    return false;
}

static void state_view_enter(void* model_ptr) {
    StateViewModel* m = model_ptr;
    m->state  = m->api->get_state(m->api);
    m->scroll = 0;
}

View* koi_state_view_alloc(KoiCoreApi* api) {
    View* view = view_alloc();
    view_set_draw_callback(view, state_view_draw);
    view_set_input_callback(view, state_view_input);
    view_set_enter_callback(view, state_view_enter);
    view_allocate_model(view, ViewModelTypeLocking, sizeof(StateViewModel));

    StateViewModel* m = view_get_model(view);
    m->api    = api;
    m->scroll = 0;
    view_commit_model(view, false);

    return view;
}

void koi_state_view_free(View* view) {
    view_free(view);
}
