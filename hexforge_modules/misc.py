import ida_kernwin
import idaapi
import binascii
import re

from hexforge_modules import helper

REGEX_HEX = re.compile(r"[^0-9a-fA-F]")


class PatchMemory(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::patch_memory"
        self.ACTION_TEXT = "patch_memory"
        self.ACTION_TOOLTIP = "patch_memory"

    # function to execute
    def _action(self) -> None:
        data = self._show()
        helper.write_bytes_to_selected(data)

    def _show(self):
        f = self.InputFormT()
        f, args = f.Compile()
        # Show form
        ok = f.Execute()
        if ok == 1:
            data_input = f.hex_data.value
            try:
                if f.Data_UTF8.checked:  # ascii data
                    data = data_input.encode()
                else:  # hex data
                    data = binascii.unhexlify(re.sub(REGEX_HEX, "", data_input))
            except binascii.Error as e:
                print(e)
                data = None
            f.Free()
            return data

        else:
            f.Free()
            return None

    class InputFormT(ida_kernwin.Form):
        def __init__(self):
            self.__n = 0
            F = ida_kernwin.Form
            F.__init__(
                self,
                r"""BUTTON YES* Ok
                        Patch memory Settings

                        {FormChangeCb}
                        <Data UTF8:{Data_UTF8}>{cData_UTF8Group}>
                        <##Data :{hex_data}>
                        """,
                {
                    "FormChangeCb": F.FormChangeCb(self.OnFormChange),
                    "cData_UTF8Group": F.ChkGroupControl(("Data_UTF8",)),
                    "hex_data": F.MultiLineTextControl(
                        text="", flags=F.MultiLineTextControl.TXTF_FIXEDFONT
                    ),
                },
            )

        def OnFormChange(self, fid):
            return 1


class NopMemory(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::nop_memory"
        self.ACTION_TEXT = "nop_memory"
        self.ACTION_TOOLTIP = "nop_memory"

    def _action(self) -> None:
        self._nop_selected_bytes()

    def _nop_selected_bytes(self):
        data = helper.get_selected_bytes()
        if data is None:
            idaapi.msg("Failed to get selected bytes.\n")
            return

        # create NOP array with the size of the selection
        nop_data = bytearray(len(data))
        nop_data[:] = b"\x90" * len(data)

        # write the NOPs to the selected address range
        helper.write_bytes_to_selected(nop_data)


class CopyMemory(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::copy_memory"
        self.ACTION_TEXT = "copy_memory"
        self.ACTION_TOOLTIP = "copy_memory"

    def _action(self) -> None:
        from PyQt5.Qt import QApplication

        data = helper.get_selected_bytes()
        try:
            QApplication.clipboard().setText(binascii.hexlify(data).decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError) as e:
            print(e)
            return None

class DumpMemory(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::dump_memory"
        self.ACTION_TEXT = "dump_memory"
        self.ACTION_TOOLTIP = "dump_memory"

    # function to execute
    def _action(self) -> None:
        result = self._show()
        if result:
            start_addr, end_addr, filepath = result
            self.dump_memory_to_file(start_addr, end_addr, filepath)

    def _show(self):
        f = self.InputFormT()
        f, args = f.Compile()
        # Show form
        ok = f.Execute()
        if ok == 1:
            start_addr = int(f.start_addr.value, 16)
            end_addr = int(f.end_addr.value, 16)
            filepath = f.filepath.value
            f.Free()
            return start_addr, end_addr, filepath
        else:
            f.Free()
            return None

    def dump_memory_to_file(self, start_addr, end_addr, filepath):
        size = end_addr - start_addr
        data = idaapi.get_bytes(start_addr, size)
        if data:
            with open(filepath, 'wb') as f:
                f.write(data)
            print(f"Memory dumped to {filepath}")
        else:
            print("Failed to read memory")

    class InputFormT(ida_kernwin.Form):
        def __init__(self):
            self.__n = 0
            F = ida_kernwin.Form
            F.__init__(
                self,
                r"""BUTTON YES* Ok
                        Dump Memory

                        {FormChangeCb}
                        <Start Address    :{start_addr}>
                        <End Address      :{end_addr}>
                        <Filepath         :{filepath}>
                        """,
                {
                    "FormChangeCb": F.FormChangeCb(self.OnFormChange),
                    "start_addr": F.StringInput(),
                    "end_addr": F.StringInput(),
                    "filepath": F.StringInput(),
                },
            )

        def OnFormChange(self, fid):
            return 1