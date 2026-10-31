"""Actual Tk layout regressions: narrow forms, large fonts and scroll reachability."""
import tkinter as tk
from tkinter import ttk
from unittest.mock import patch
import pytest
from keyvault.app import Application
from keyvault import keys
from keyvault.widgets import ScrollableFrame
from tests.test_ui import descendants, dialog


def assert_readable(win):
    for widget in descendants(win):
        if not widget.winfo_ismapped(): continue
        if isinstance(widget, (ttk.Label, ttk.Button, ttk.Checkbutton)):
            # Vertical overflow inside a scroll viewport is intentional; horizontal clipping is not.
            assert widget.winfo_width() >= widget.winfo_reqwidth() - 2, (widget.cget('text'), widget.winfo_width(), widget.winfo_reqwidth())
            assert widget.winfo_rootx() + widget.winfo_width() <= widget.master.winfo_rootx() + widget.master.winfo_width() + 2, widget.cget('text')
    for widget in descendants(win.actions):
        if isinstance(widget, ttk.Button):
            assert widget.winfo_ismapped()
            assert widget.winfo_rooty() + widget.winfo_height() <= win.winfo_rooty() + win.winfo_height()


@pytest.mark.parametrize('scaling', [4/3, 2, 8/3])
def test_all_forms_at_narrow_width_and_large_fonts(tmp_path, scaling):
    root = tk.Tk(); original_scale = root.tk.call('tk', 'scaling'); root.tk.call('tk', 'scaling', scaling)
    app = Application(root, preferences_path=tmp_path/'prefs.json')
    errors = []; root.report_callback_exception = lambda *a: errors.append(a[1])
    try:
        app.vault.create(tmp_path/'layout.okv', 'synthetic layout password')
        rid, _ = app.vault.add(keys.generate('Ed25519'), '较长的测试密钥名称' * 8, '布局,本地', '测试备注' * 40)
        app.show_manager(); app.tree.selection_set(rid); app.show_detail(); root.update()
        methods = [app.generate_dialog, app.import_dialog, app.edit_dialog,
                   lambda: app.export_dialog(False), lambda: app.export_dialog(True),
                   app.convert_key_dialog, app.convert_public_dialog, app.view_key_dialog,
                   app.export_original_dialog, app.export_settings_dialog,
                   app.pair_check_dialog, app.security_dialog, app.token_dialog,
                   app.password_dialog, app.help_dialog]
        for method in methods:
            method(); win = dialog(root); win.geometry('580x500'); root.update()
            assert_readable(win)
            canvas = win.viewport.canvas
            # Entire form can be reached, even with high DPI and multiple wrapped paragraphs.
            win.focus_force(); root.update()
            canvas.yview_moveto(1); root.update()
            assert canvas.yview()[1] >= .999, (win.title(), canvas.yview())
            assert_readable(win)
            win.destroy(); root.update()
        assert not errors, errors
    finally:
        root.tk.call('tk', 'scaling', original_scale)
        app.quit()


def test_focus_scrolls_hidden_field_into_view_and_layout_reflows(tmp_path):
    root = tk.Tk(); app = Application(root, preferences_path=tmp_path/'prefs.json')
    try:
        app.convert_key_dialog(); win = dialog(root); win.geometry('580x500'); root.update()
        entries = [w for w in descendants(win) if type(w) == ttk.Entry]
        pane = win.viewport.content
        notice = ttk.Label(pane, text='Synthetic long notice\n' * 35)
        notice.pack(before=pane.pack_slaves()[0], fill='x')
        root.update()
        last = entries[-1]; last.focus_force(); root.update()
        canvas = win.viewport.canvas
        assert canvas.yview()[0] > 0
        assert canvas.winfo_rooty() <= last.winfo_rooty()
        assert last.winfo_rooty() + last.winfo_height() <= canvas.winfo_rooty() + canvas.winfo_height()
        # Proportional shrinking retains the two-column layout; genuine long content scrolls.
        first_column = entries[0].master.master
        second_column = entries[-1].master.master
        assert second_column.winfo_y() == first_column.winfo_y()
        win.geometry('940x740'); root.update()
        assert second_column.winfo_y() == first_column.winfo_y()
        assert_readable(win)
    finally: app.quit()


def test_long_notice_does_not_displace_pair_actions(tmp_path):
    root = tk.Tk(); app = Application(root, preferences_path=tmp_path/'prefs.json')
    try:
        app.pair_check_dialog(); win = dialog(root); win.geometry('580x500'); root.update()
        result = next(w for w in descendants(win) if isinstance(w, ttk.Label) and w.cget('text') == '等待校验')
        result.configure(text='匹配：' + '完整校验范围与长指纹 ' * 80); root.update()
        assert_readable(win)
        assert win.viewport.canvas.winfo_height() > 200
    finally: app.quit()


def test_local_picker_long_names_can_scroll_horizontally(tmp_path):
    from keyvault.localdialog import askopenfilename
    root = tk.Tk(); app = Application(root, preferences_path=tmp_path/'prefs.json')
    errors = []
    (tmp_path / ('long-name-' * 20 + '.txt')).write_text('synthetic')
    def check():
        win = dialog(root)
        try:
            win.geometry('650x480'); root.update()
            box = next(w for w in descendants(win) if isinstance(w, tk.Listbox))
            assert box.xview()[1] < 1
            box.xview_moveto(1); root.update()
            assert box.xview()[1] >= .999
            for w in descendants(win):
                if isinstance(w, ttk.Button):
                    assert w.winfo_ismapped()
                    assert w.winfo_width() >= w.winfo_reqwidth() - 2
        except Exception as error: errors.append(error)
        finally: win.destroy()
    try:
        root.after(150, check)
        askopenfilename(parent=root, initialdir=str(tmp_path))
        assert not errors, errors
    finally: app.quit()


def test_large_fonts_on_small_display_keep_both_manager_panes_reachable(tmp_path):
    root = tk.Tk(); original = root.tk.call('tk', 'scaling'); root.tk.call('tk', 'scaling', 8/3)
    app = None
    try:
        with patch.object(root, 'winfo_screenwidth', return_value=1024), patch.object(root, 'winfo_screenheight', return_value=768):
            app = Application(root, preferences_path=tmp_path/'prefs.json')
            app.vault.create(tmp_path/'small.okv', 'synthetic layout password')
            app.show_manager(); root.update()
            assert app.tree.winfo_ismapped() and app.tree.winfo_width() > 200
            button = app.detail_buttons['删除记录']
            viewport = next(w for w in descendants(root) if isinstance(w, ScrollableFrame) and str(button).startswith(str(w.content)+'.'))
            viewport.canvas.yview_moveto(1); root.update()
            assert button.winfo_width() >= button.winfo_reqwidth()
            assert button.winfo_rooty() + button.winfo_height() <= viewport.canvas.winfo_rooty() + viewport.canvas.winfo_height()
    finally:
        root.tk.call('tk', 'scaling', original)
        if app: app.quit()
        else: root.destroy()


def test_compact_pages_do_not_show_unused_scrollbars(tmp_path):
    root = tk.Tk(); app = Application(root, preferences_path=tmp_path/'prefs.json')
    try:
        for method in (app.export_settings_dialog, app.token_dialog, app.convert_key_dialog):
            method(); win = dialog(root); root.update()
            assert win.viewport.canvas.yview() == (0.0, 1.0), (win.title(), win.viewport.canvas.yview())
            assert not win.viewport.scrollbar.winfo_ismapped(), win.title()
            for w in descendants(win):
                if isinstance(w, ttk.Scrollbar): assert not w.winfo_ismapped(), (win.title(), str(w))
            if method == app.token_dialog:
                win.geometry('720x608'); root.update()
                assert win.viewport.canvas.yview() == (0.0, 1.0)
                assert not win.viewport.scrollbar.winfo_ismapped()
            win.destroy(); root.update()
        # A genuinely overflowing form still needs a working scrollbar; growing it hides it again.
        app.export_settings_dialog(); win = dialog(root); win.geometry('608x464'); root.update()
        assert not win.viewport.scrollbar.winfo_ismapped()
        notice = ttk.Label(win.viewport.content, text='Synthetic long notice\n' * 8)
        notice.pack(fill='x'); root.update()
        assert win.viewport.scrollbar.winfo_ismapped()
        win.viewport.canvas.yview_moveto(1); root.update()
        assert win.viewport.canvas.yview()[1] >= .999
        notice.destroy(); win.geometry('912x696'); root.update()
        assert not win.viewport.scrollbar.winfo_ismapped()
    finally: app.quit()


def test_password_eye_is_inline_keyboard_operable_and_masks_on_leaving(tmp_path):
    root = tk.Tk(); app = Application(root, preferences_path=tmp_path/'prefs.json')
    try:
        win, pane = app.dialog('eye test')
        entry = app.field(pane, 'Password', secret=True)
        other = app.field(pane, 'Other')
        entry.insert(0, 'synthetic input only'); root.update()
        eye = entry.visibility_button
        assert eye.cget('image') and eye.cget('text') == '显示密码'
        assert eye.master == entry.master
        assert eye.winfo_rootx() >= entry.winfo_rootx() + entry.winfo_width()
        entry.focus_force(); root.update(); eye.invoke(); assert entry.cget('show') == ''
        eye.focus_force(); root.update(); assert entry.cget('show') == ''
        eye.event_generate('<Return>'); root.update(); assert entry.cget('show')
        eye.invoke(); assert entry.cget('show') == ''
        other.focus_force(); root.update(); assert entry.cget('show')
        assert entry.get() == 'synthetic input only'
        entry.configure(state='disabled'); eye.invoke(); assert entry.cget('show')
    finally: app.quit()


def test_hardware_ui_resets_keys_when_device_or_driver_changes(tmp_path):
    from unittest.mock import MagicMock
    root = tk.Tk(); app = Application(root, preferences_path=tmp_path/'prefs.json')
    try:
        app.token_dialog(); win = dialog(root); root.update()
        buttons = {w.cget('text'): w for w in descendants(win) if isinstance(w, ttk.Button)}
        assert buttons['读取'].instate(['disabled'])
        assert buttons['验证签名'].instate(['disabled'])
        combos = [w for w in descendants(win) if isinstance(w, ttk.Combobox)]
        fields = [w for w in descendants(win) if type(w) == ttk.Entry]
        token = MagicMock(); token.slots.return_value = [{'label':'synthetic A','serial':'1','slot':1}, {'label':'synthetic B','serial':'2','slot':2}]
        token.public_keys.return_value = [{'label':'test key','id':'1234','public':keys.generate('RSA-2048').public_key()}]
        with patch('keyvault.token.PKCS11Token', return_value=token), patch('keyvault.token_ui.messagebox.askyesno', return_value=True):
            buttons['核对并连接'].invoke(); assert not buttons['读取'].instate(['disabled'])
            buttons['读取'].invoke(); assert not buttons['验证签名'].instate(['disabled'])
            combos[0].current(1); combos[0].event_generate('<<ComboboxSelected>>'); root.update()
            assert buttons['验证签名'].instate(['disabled'])
            buttons['读取'].invoke(); assert not buttons['验证签名'].instate(['disabled'])
            fields[0].insert(0, 'changed local module'); root.update()
            assert buttons['读取'].instate(['disabled']) and buttons['验证签名'].instate(['disabled'])
    finally: app.quit()


def test_window_resize_scales_fonts_controls_and_icons_without_cumulative_drift(tmp_path):
    from tkinter import font
    root = tk.Tk(); app = Application(root, preferences_path=tmp_path/'prefs.json')
    errors = []; root.report_callback_exception = lambda *a: errors.append(a[1])
    try:
        app.convert_key_dialog(); win = dialog(root); root.update()
        entries = [w for w in descendants(win) if type(w) == ttk.Entry]
        entry = entries[-1]; eye = entry.visibility_button
        title = next(w for w in descendants(win) if isinstance(w, ttk.Label))
        size = font.Font(root=root, font=title.cget('font')).actual()['size']
        family = font.Font(root=root, font=title.cget('font')).actual()['family']
        original_height = entry.winfo_height(); icon_width = eye._icons[0].width()
        # Respect the current desktop's client-size limit (remote displays can be shorter).
        base = win._scaler.base
        zoom = next(z for z in (1.5, 1.4, 1.3, 1.2, 1.1) if all(round(b*z) <= m for b,m in zip(base,win.maxsize())))
        win.geometry(f'{round(base[0]*zoom)}x{round(base[1]*zoom)}'); root.update()
        assert win._layout_zoom == zoom
        assert font.Font(root=root, font=title.cget('font')).actual()['size'] == round(size*zoom)
        assert entry.winfo_height() > original_height
        assert eye._icons[0].width() == round(icon_width*zoom)
        # Programmatic wrong-aspect requests also correct the outer window, with no letterboxing.
        win.geometry('1410x740'); root.update(); assert win._layout_zoom == 1
        assert win.winfo_width() == win._stage.winfo_width() == 940
        assert win.winfo_height() == win._stage.winfo_height() == 740
        win.geometry('752x592'); root.update(); assert win._layout_zoom == .8
        assert font.Font(root=root, font=title.cget('font')).actual()['size'] == round(size*.8)
        for _ in range(3):
            win.geometry('1128x888'); root.update()
            win.geometry('940x740'); root.update()
        assert font.Font(root=root, font=title.cget('font')).actual()['size'] == size
        assert font.Font(root=root, font=title.cget('font')).actual()['family'] == family
        assert entry.winfo_height() == original_height
        assert eye._icons[0].width() == icon_width
        win.destroy()
        app.vault.create(tmp_path/'nav-zoom.okv', 'synthetic layout password')
        app.show_manager(); root.update()
        base = root._scaler.base
        zoom = next(z for z in (1.5, 1.4, 1.3, 1.2, 1.1) if all(round(b*z) <= m for b,m in zip(base,root.maxsize())))
        root.geometry(f'{round(base[0]*zoom)}x{round(base[1]*zoom)}'); root.update()
        app.set_filter('private'); root.update()
        style = ttk.Style(root)
        sizes = {font.Font(root=root, font=style.lookup(button.cget('style'), 'font')).actual()['size'] for button in app.nav_buttons.values()}
        assert sizes == {round(12*zoom)}, sizes
        assert not errors, errors
    finally: app.quit()


def test_dashboard_uses_readable_type_and_available_vertical_space(tmp_path):
    from tkinter import font
    root = tk.Tk(); app = Application(root, preferences_path=tmp_path/'prefs.json')
    try:
        app.vault.create(tmp_path/'readability.okv', 'synthetic layout password')
        app.show_manager(); root.update()
        for zoom in (.8, 1):
            base = root._scaler.base
            root.geometry(f'{round(base[0]*zoom)}x{round(base[1]*zoom)}'); root.update()
            style = ttk.Style(root)
            for button in app.nav_buttons.values():
                assert font.Font(root=root, font=style.lookup(button.cget('style'),'font')).actual()['size'] >= 10
            assert font.Font(root=root, font=app.detail.cget('font')).actual()['size'] >= 10
            for text in ('不联网 · 不上传',):
                label = next(w for w in descendants(root) if isinstance(w,ttk.Label) and w.cget('text')==text)
                bottom = label.winfo_rooty()+label.winfo_height()
                assert root.winfo_rooty()+root.winfo_height()-30 <= bottom <= root.winfo_rooty()+root.winfo_height()
            button = app.detail_buttons['删除记录']
            viewport = next(w for w in descendants(root) if isinstance(w,ScrollableFrame) and str(button).startswith(str(w.content)+'.'))
            assert not viewport.scrollbar.winfo_ismapped()
            assert abs(button.winfo_rooty()+button.winfo_height() - (viewport.canvas.winfo_rooty()+viewport.canvas.winfo_height())) < 12
            assert app.detail.winfo_height() >= 90
    finally: app.quit()
