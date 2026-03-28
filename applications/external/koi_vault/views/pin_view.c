// applications/external/koi_vault/views/pin_view.c
#include "pin_view.h"

#include <gui/canvas.h>
#include <gui/elements.h>
#include <furi.h>
#include <string.h>

#define PIN_MAX_DIGITS 16
#define PIN_MIN_DIGITS 4

typedef struct {
    char digits[PIN_MAX_DIGITS + 1]; // null-terminated
    uint8_t length;                   // current number of digits
    uint8_t cursor;                   // position being edited (0..length)
    char header[32];
    PinViewCallback callback;
    void* callback_context;
} PinViewModel;

static void pin_view_draw(Canvas* canvas, void* model_ptr) {
    PinViewModel* m = model_ptr;
    canvas_clear(canvas);

    // Header
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 2, AlignCenter, AlignTop, m->header);

    // PIN dot display
    canvas_set_font(canvas, FontBigNumbers);
    uint8_t dot_y = 28;
    uint8_t start_x = (uint8_t)(64 - (m->length * 8) / 2);
    if(start_x < 4) start_x = 4;

    for(uint8_t i = 0; i < m->length; i++) {
        uint8_t x = (uint8_t)(start_x + i * 10);
        if(i == m->cursor) {
            // Show the actual digit at cursor position
            char ch[2] = {m->digits[i], '\0'};
            canvas_draw_str(canvas, x, dot_y, ch);
        } else {
            // Show asterisk for other positions
            canvas_draw_disc(canvas, (int16_t)(x + 3), (int16_t)(dot_y - 4), 3);
        }
    }

    // Cursor indicator
    if(m->length < PIN_MAX_DIGITS) {
        uint8_t cx = (uint8_t)(start_x + m->length * 10);
        canvas_draw_str(canvas, cx, dot_y, "_");
    }

    // Instructions
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 50, "U/D:digit L/R:move");
    canvas_draw_str(canvas, 2, 62, "OK:confirm  Back:cancel");

    // Show length indicator
    char len_str[16];
    snprintf(len_str, sizeof(len_str), "%d/%d", m->length, PIN_MAX_DIGITS);
    canvas_draw_str(canvas, 100, 50, len_str);
}

static bool pin_view_input(InputEvent* event, void* model_ptr) {
    PinViewModel* m = model_ptr;

    if(event->type != InputTypePress && event->type != InputTypeRepeat) return false;

    switch(event->key) {
    case InputKeyUp:
        if(m->cursor < m->length) {
            // Increment digit at cursor
            if(m->digits[m->cursor] >= '9') m->digits[m->cursor] = '0';
            else m->digits[m->cursor]++;
        } else if(m->length < PIN_MAX_DIGITS) {
            // Add new digit
            m->digits[m->length] = '0';
            m->length++;
        }
        return true;

    case InputKeyDown:
        if(m->cursor < m->length) {
            // Decrement digit at cursor
            if(m->digits[m->cursor] <= '0') m->digits[m->cursor] = '9';
            else m->digits[m->cursor]--;
        } else if(m->length > 0) {
            // Delete last digit
            m->length--;
            m->digits[m->length] = '\0';
            if(m->cursor > m->length) m->cursor = m->length;
        }
        return true;

    case InputKeyLeft:
        if(m->cursor > 0) m->cursor--;
        return true;

    case InputKeyRight:
        if(m->cursor < m->length) m->cursor++;
        return true;

    case InputKeyOk:
        if(m->length >= PIN_MIN_DIGITS && m->callback) {
            m->digits[m->length] = '\0';
            m->callback(m->digits, m->callback_context);
        }
        return true;

    default:
        break;
    }
    return false;
}

static void pin_view_enter(void* model_ptr) {
    PinViewModel* m = model_ptr;
    m->length = 0;
    m->cursor = 0;
    memset(m->digits, 0, sizeof(m->digits));
}

View* koi_pin_view_alloc(void) {
    View* view = view_alloc();
    view_set_draw_callback(view, pin_view_draw);
    view_set_input_callback(view, pin_view_input);
    view_set_enter_callback(view, pin_view_enter);
    view_allocate_model(view, ViewModelTypeLocking, sizeof(PinViewModel));

    PinViewModel* m = view_get_model(view);
    memset(m, 0, sizeof(PinViewModel));
    strncpy(m->header, "Enter PIN", 31);
    view_commit_model(view, false);

    return view;
}

void koi_pin_view_free(View* view) {
    // Wipe PIN digits from model memory
    PinViewModel* m = view_get_model(view);
    memset(m->digits, 0, sizeof(m->digits));
    view_commit_model(view, false);
    view_free(view);
}

void koi_pin_view_set_callback(View* view, PinViewCallback callback, void* context) {
    PinViewModel* m = view_get_model(view);
    m->callback = callback;
    m->callback_context = context;
    view_commit_model(view, false);
}

void koi_pin_view_set_header(View* view, const char* header) {
    PinViewModel* m = view_get_model(view);
    strncpy(m->header, header, 31);
    m->header[31] = '\0';
    view_commit_model(view, false);
}

void koi_pin_view_reset(View* view) {
    PinViewModel* m = view_get_model(view);
    m->length = 0;
    m->cursor = 0;
    memset(m->digits, 0, sizeof(m->digits));
    view_commit_model(view, true);
}
