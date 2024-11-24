import idaapi
import idc
import ida_hexrays
import ida_kernwin
# IDA python functions


def get_selected_bytes() -> bytearray:
    """
    The function generates a bytearray of selected bytes in IDA. If no bytes are selected, it returns the byte at the current cursor position.

    :return: A bytearray of the selected bytes or the byte at the current cursor position if no selection is made.
    """
    success, start, end = idaapi.read_range_selection(None)
    if not success:
        return bytearray(idaapi.get_bytes(idc.here(), 1))
    size = end - start
    return bytearray(idaapi.get_bytes(start, size))


def write_bytes_to_selected(data) -> None:
    """
    The function writes the given bytes data to the selected memory region in IDA. If no region is selected, it writes to the current cursor position.

    :param data: The byte data to write to the selected memory region.
    :return: None
    """
    if data:
        success, start, _ = idaapi.read_range_selection(None)
        # if user did not select a memory region, get current cursor address
        if not success:
            start = idc.here()
        if start == -1:
            return None
        for i, x in enumerate(data):
            idaapi.patch_byte(start + i, x)

def get_highighted_string_from_decompiler() -> str:
    """
    Get the highlighted string from the decompiler view in IDA Pro.

    :return: The highlighted string or an empty string if no text is highlighted.
    """
    widget = ida_kernwin.get_current_widget()
    if widget and ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
        vu = ida_hexrays.get_widget_vdui(widget)
        if vu:
            highlighted_text = ida_kernwin.get_highlight(vu.ct)
            if highlighted_text:
                return highlighted_text[0]
    return ""

# Template class for modules
class ModuleTemplate:
    def __init__(self):
        pass

    def init_action(self):
        action_desc = idaapi.action_desc_t(
            self.ACTION_NAME,  # The action name.
            self.ACTION_TEXT,  # The action text.
            IDACtxEntry(self._action),  # The action handler.
            None,  # Optional: action shortcut
            self.ACTION_TOOLTIP,  # Optional: tooltip
            0,  # icon
        )
        assert idaapi.register_action(action_desc), "Action registration failed"

    def del_action(self):
        idaapi.unregister_action(self.ACTION_NAME)

    # function to execute
    def _action(self):
        """
        The function to execute when the context menu is invoked.
        This should contain the main logic of the module.
        """
        pass


# IDA ctxt


class IDACtxEntry(idaapi.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return idaapi.AST_ENABLE_ALWAYS
