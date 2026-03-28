// applications/external/koi_vault/views/browser_view.c
#include "browser_view.h"

#include <gui/canvas.h>
#include <furi.h>
#include <string.h>
#include <stdio.h>

#define BROWSER_PAGE_SIZE 4

typedef struct {
    KoiVault* vault;
    uint16_t  scroll;     // top visible entry
    uint16_t  selected;   // currently selected entry
    BrowserViewCallback callback;
    void* callback_context;
} BrowserViewModel;

static void browser_view_draw(Canvas* canvas, void* model_ptr) {
    BrowserViewModel* m = model_ptr;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);

    uint16_t count = koi_vault_file_count(m->vault);

    // Header
    char header[32];
    snprintf(header, sizeof(header), "Vault Files (%d)", count);
    canvas_draw_str(canvas, 2, 10, header);
    canvas_draw_line(canvas, 0, 12, 128, 12);

    if(count == 0) {
        canvas_draw_str(canvas, 20, 36, "Empty vault");
        canvas_draw_str(canvas, 10, 48, "OK: add file");
        return;
    }

    // File list
    for(uint8_t i = 0; i < BROWSER_PAGE_SIZE; i++) {
        uint16_t idx = m->scroll + i;
        if(idx >= count) break;

        const KoiVaultIndexEntry* entry = koi_vault_file_get(m->vault, idx);
        if(!entry) break;

        uint8_t y = (uint8_t)(24 + i * 12);
        bool is_selected = (idx == m->selected);

        if(is_selected) {
            canvas_draw_box(canvas, 0, (int16_t)(y - 9), 128, 12);
            canvas_set_color(canvas, ColorWhite);
        }

        char row[48];
        snprintf(row, sizeof(row), "%.20s  %luB", entry->name, (unsigned long)entry->size);
        canvas_draw_str(canvas, 4, y, row);

        if(is_selected) canvas_set_color(canvas, ColorBlack);
    }

    // Scroll indicators
    if(m->scroll > 0) canvas_draw_str(canvas, 120, 20, "^");
    if(m->scroll + BROWSER_PAGE_SIZE < count) canvas_draw_str(canvas, 120, 60, "v");

    // Bottom bar
    canvas_draw_str(canvas, 2, 63, "OK:view  L:add  R:del");
}

static bool browser_view_input(InputEvent* event, void* model_ptr) {
    BrowserViewModel* m = model_ptr;
    uint16_t count = koi_vault_file_count(m->vault);

    if(event->type != InputTypePress && event->type != InputTypeRepeat) return false;

    switch(event->key) {
    case InputKeyUp:
        if(m->selected > 0) {
            m->selected--;
            if(m->selected < m->scroll) m->scroll = m->selected;
        }
        return true;

    case InputKeyDown:
        if(count > 0 && m->selected < count - 1) {
            m->selected++;
            if(m->selected >= m->scroll + BROWSER_PAGE_SIZE)
                m->scroll = (uint16_t)(m->selected - BROWSER_PAGE_SIZE + 1);
        }
        return true;

    case InputKeyOk:
        if(count == 0) {
            if(m->callback) m->callback(BrowserActionAdd, 0, m->callback_context);
        } else {
            if(m->callback) m->callback(BrowserActionView, m->selected, m->callback_context);
        }
        return true;

    case InputKeyLeft:
        if(m->callback) m->callback(BrowserActionAdd, 0, m->callback_context);
        return true;

    case InputKeyRight:
        if(count > 0 && m->callback)
            m->callback(BrowserActionDelete, m->selected, m->callback_context);
        return true;

    default:
        break;
    }
    return false;
}

static void browser_view_enter(void* model_ptr) {
    BrowserViewModel* m = model_ptr;
    m->scroll = 0;
    m->selected = 0;
}

View* koi_browser_view_alloc(KoiVault* vault) {
    View* view = view_alloc();
    view_set_draw_callback(view, browser_view_draw);
    view_set_input_callback(view, browser_view_input);
    view_set_enter_callback(view, browser_view_enter);
    view_allocate_model(view, ViewModelTypeLocking, sizeof(BrowserViewModel));

    BrowserViewModel* m = view_get_model(view);
    m->vault = vault;
    m->scroll = 0;
    m->selected = 0;
    view_commit_model(view, false);

    return view;
}

void koi_browser_view_free(View* view) {
    view_free(view);
}

void koi_browser_view_set_callback(View* view, BrowserViewCallback callback, void* context) {
    BrowserViewModel* m = view_get_model(view);
    m->callback = callback;
    m->callback_context = context;
    view_commit_model(view, false);
}

void koi_browser_view_refresh(View* view) {
    BrowserViewModel* m = view_get_model(view);
    m->scroll = 0;
    m->selected = 0;
    view_commit_model(view, true);
}
