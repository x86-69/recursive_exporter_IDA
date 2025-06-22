#---------------------------------------------------------------------
#
#  IDA Pro Python Plugin: Recursive Function Exporter
#
#  This plugin recursively exports the decompilation or disassembly of
#  all functions called from a selected entry-point function. It also
#  identifies and exports any global variables referenced by these
#  functions.
#
#  This version integrates with the right-click context menu in the
#  Disassembly and Pseudocode views.
#
#
#  Instructions:
#  1. Place this script in your IDA Pro 'plugins' directory.
#  2. Start or restart IDA. The plugin loads automatically.
#  3. In the Disassembly or Pseudocode view, right-click inside a function.
#  4. Navigate to the "Recursive Export" submenu.
#  5. Choose either "Export Decompile" or "Export Disassembly".
#
#---------------------------------------------------------------------

import idaapi
import idc
import idautils
import ida_funcs
import ida_kernwin
import ida_hexrays
import ida_segment
import ida_bytes
import ida_nalt
from collections import deque

# --- Constants ---
PLUGIN_NAME = "Recursive Function Exporter"
ACTION_DECOMPILE_NAME = "exporter:decompile"
ACTION_DISASSEMBLE_NAME = "exporter:disassemble"
MAX_SIZE_VAR = 128

# --- Core Logic ---

class CallVisitor(ida_hexrays.ctree_visitor_t):
    """
    Visits all expressions in a decompiled function's c-tree
    to collect the addresses of all function calls. This is the most
    accurate way to find callees.
    """
    def __init__(self):
        super(CallVisitor, self).__init__(ida_hexrays.CV_FAST)
        self.callees = set()

    def visit_expr(self, expr):
        if expr.op == ida_hexrays.cot_call:
            called_ea = expr.x.obj_ea
            if called_ea != idaapi.BADADDR:
                target_func = ida_funcs.get_func(called_ea)
                if target_func and not (target_func.flags & idaapi.FUNC_LIB):
                    self.callees.add(target_func.start_ea)
        return 0

def get_callees_and_globals(func_ea, use_hexrays):
    """
    Analyzes a function to find callees and referenced globals.
    Prioritizes using the decompiler c-tree for finding calls.
    """
    callees = set()
    globals_ref = set()
    
    f = ida_funcs.get_func(func_ea)
    if not f:
        return callees, globals_ref

    # --- Find Callees using the most accurate method available ---
    decompiler_succeeded = False
    if use_hexrays:
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                visitor = CallVisitor()
                visitor.apply_to(cfunc.body, None)
                callees = visitor.callees
                decompiler_succeeded = True
        except ida_hexrays.DecompilationFailure:
            idaapi.msg("Decompilation failed for 0x{:X}, falling back to xref analysis to find callees.\n".format(func_ea))
            
    # Fallback to disassembly analysis if decompiler fails or is unavailable
    if not decompiler_succeeded:
        for head in idautils.FuncItems(func_ea):
            for xref in idautils.XrefsFrom(head, 0):
                if xref.type in (idaapi.fl_CN, idaapi.fl_CF):
                    target_func = ida_funcs.get_func(xref.to)
                    if target_func and not (target_func.flags & idaapi.FUNC_LIB):
                        callees.add(target_func.start_ea)

    # --- Find Globals (this method is reliable) ---
    for head in idautils.FuncItems(func_ea):
        for xref in idautils.XrefsFrom(head, 0):
            if xref.type in (idaapi.dr_R, idaapi.dr_W, idaapi.dr_O):
                target_seg = ida_segment.getseg(xref.to)
                if target_seg and target_seg.type in (idaapi.SEG_DATA, idaapi.SEG_BSS):
                    globals_ref.add(xref.to)
                    
    return callees, globals_ref

def get_function_disassembly(func_ea):
    """Generates the disassembly for a given function."""
    f = ida_funcs.get_func(func_ea)
    if not f:
        return f"// ERROR: Could not find function at 0x{func_ea:X}\n"
    disasm = [f"// Disassembly for function: {idc.get_func_name(func_ea)} at 0x{func_ea:X}\n"]
    current_ea = f.start_ea
    while current_ea < f.end_ea:
        disasm.append(idc.generate_disasm_line(current_ea, 0))
        current_ea = idc.next_head(current_ea, f.end_ea)
    return "\n".join(disasm) + "\n"

def get_variable_definition(ea):
    """
    Formats a line describing a global variable. If the variable's size
    is MAX_SIZE_VAR bytes or less, its content will also be printed.
    """
    seg = ida_segment.getseg(ea)
    if not seg:
        return f"// ERROR: Could not find segment for address 0x{ea:X}"
    
    seg_name = ida_segment.get_segm_name(seg)
    name = idc.get_name(ea)
    if not name:
        name = f"unk_{ea:X}"
        
    size = ida_bytes.get_item_size(ea)
    
    content_str = ""
    # Check if size is valid (greater than 0) and within the threshold
    if 0 < size <= MAX_SIZE_VAR:
        # Read the raw bytes of the variable from the database
        content_bytes = ida_bytes.get_bytes(ea, size)
        if content_bytes:
            # Format the bytes into a more readable hex string: "[01, 23, AB, CD]"
            hex_parts = [f"{b:02X}" for b in content_bytes]
            content_str = f"; [{', '.join(hex_parts)}] "

    # Combine all parts into the final formatted string
    return f"{seg_name}:{ea:016X} {name:<25} {content_str}; Size: {size} bytes"

def perform_export(force_disassembly=False):
    """The main logic for performing the recursive export."""
    use_hexrays = ida_hexrays.init_hexrays_plugin()
    if not use_hexrays and not force_disassembly:
        ida_kernwin.warning("Cannot decompile; Hex-Rays is not available. Try exporting disassembly instead.")
        return
    
    current_ea = ida_kernwin.get_screen_ea()
    start_func = ida_funcs.get_func(current_ea)
    if not start_func:
        ida_kernwin.warning("Please place your cursor inside a function.")
        return

    start_func_ea = start_func.start_ea
    start_func_name = idc.get_func_name(start_func_ea)
    idaapi.msg(f"Starting recursive export from function: {start_func_name}\n")

    q = deque([start_func_ea])
    processed_funcs = set()
    all_globals = set()
    output_code = {}

    idaapi.show_wait_box("Analyzing call graph...")
    try:
        while q:
            current_func_ea = q.popleft()
            if current_func_ea in processed_funcs:
                continue
            processed_funcs.add(current_func_ea)
            
            code_block = ""
            if force_disassembly:
                code_block = get_function_disassembly(current_func_ea)
            elif use_hexrays:
                try:
                    cfunc = ida_hexrays.decompile(current_func_ea)
                    code_block = str(cfunc) if cfunc else get_function_disassembly(current_func_ea)
                except ida_hexrays.DecompilationFailure:
                    code_block = get_function_disassembly(current_func_ea)
            else: # Should not be reached due to check at start of function
                code_block = get_function_disassembly(current_func_ea)
            output_code[current_func_ea] = code_block
            
            callees, globals_ref = get_callees_and_globals(current_func_ea, use_hexrays)
            all_globals.update(globals_ref)
            for callee_ea in callees:
                if callee_ea not in processed_funcs:
                    q.append(callee_ea)
    finally:
        idaapi.hide_wait_box()

    output_file_path = ida_kernwin.ask_file(1, "*.txt", "Save Recursive Export")
    if not output_file_path:
        idaapi.msg("Export cancelled by user.\n")
        return
        
    idaapi.msg(f"Writing output to {output_file_path}...\n")
    try:
        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(f"// Recursive function export starting from: {start_func_name}\n")
            f.write(f"// Export mode: {'Disassembly' if force_disassembly else 'Decompile'}\n")
            f.write(f"// Total functions found: {len(processed_funcs)}\n")
            f.write(f"// Total global variables referenced: {len(all_globals)}\n")
            f.write("\n" + "="*80 + "\n\n")

            if all_globals:
                f.write("// --- REFERENCED GLOBAL VARIABLES ---\n\n")
                for glob_ea in sorted(list(all_globals)):
                    f.write(get_variable_definition(glob_ea) + "\n")
                f.write("\n" + "="*80 + "\n\n")
            
            f.write("// --- RECURSIVELY CALLED FUNCTIONS ---\n\n")
            for func_ea in sorted(list(processed_funcs)):
                f.write(output_code.get(func_ea, f"// ERROR: Code not found for 0x{func_ea:X}\n"))
                f.write("\n" + "-"*40 + "\n\n")
                
        ida_kernwin.info(f"Successfully exported {len(processed_funcs)} functions to\n{output_file_path}")
    except IOError as e:
        ida_kernwin.warning(f"Error writing to file: {e}")
    idaapi.msg("Export complete.\n")

# --- UI Integration ---

class DecompileExportHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        perform_export(force_disassembly=False)
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type in (idaapi.BWN_PSEUDOCODE, idaapi.BWN_DISASM) else idaapi.AST_DISABLE_FOR_WIDGET

class DisassemblyExportHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        perform_export(force_disassembly=True)
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type in (idaapi.BWN_PSEUDOCODE, idaapi.BWN_DISASM) else idaapi.AST_DISABLE_FOR_WIDGET

class ExporterUIHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle):
        if idaapi.get_widget_type(widget) in (idaapi.BWN_PSEUDOCODE, idaapi.BWN_DISASM):
            idaapi.attach_action_to_popup(widget, popup_handle, ACTION_DECOMPILE_NAME, "Recursive Export/")
            idaapi.attach_action_to_popup(widget, popup_handle, ACTION_DISASSEMBLE_NAME, "Recursive Export/")

# --- Plugin Class ---

class RecursiveExporterPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Adds right-click options to export functions recursively."
    help = "Right-click in a function to use."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""
    hooks = None

    def init(self):
        # Register decompile action
        decompile_action_desc = idaapi.action_desc_t(
            ACTION_DECOMPILE_NAME,
            "Export Decompile...",
            DecompileExportHandler(),
            None,
            "Recursively export decompilation of this function and its callees",
            199)
        idaapi.register_action(decompile_action_desc)

        # Register disassemble action
        disassemble_action_desc = idaapi.action_desc_t(
            ACTION_DISASSEMBLE_NAME,
            "Export Disassembly...",
            DisassemblyExportHandler(),
            None,
            "Recursively export disassembly of this function and its callees",
            199)
        idaapi.register_action(disassemble_action_desc)

        # Install UI hooks
        self.hooks = ExporterUIHooks()
        self.hooks.hook()
        idaapi.msg(f"{PLUGIN_NAME} loaded. Right-click in a function to use.\n")
        return idaapi.PLUGIN_KEEP

    def term(self):
        if self.hooks:
            self.hooks.unhook()
        idaapi.unregister_action(ACTION_DECOMPILE_NAME)
        idaapi.unregister_action(ACTION_DISASSEMBLE_NAME)
        idaapi.msg(f"{PLUGIN_NAME} unloaded.\n")

    def run(self, arg):
        # The run method is not used for this type of plugin,
        # but we can provide a message if the user tries to run it manually.
        idaapi.info("Recursive Exporter is already installed. Right-click in a function to use.")

# --- Plugin Registration ---

def PLUGIN_ENTRY():
    return RecursiveExporterPlugin()
