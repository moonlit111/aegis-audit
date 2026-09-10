"""Run inside IDA's console. No UI, target execution, model code, or arbitrary rule parameters."""
import json
import importlib
import inspect
from pathlib import Path
import pkgutil
import sys
import time
import traceback


def create_manager(plugin_root, work, profile, dependencies):
    sys.path.insert(0, str(dependencies))
    sys.path.insert(0, str(plugin_root))
    is_ng = (plugin_root / 'd810/core/config.py').is_file()
    if is_ng:
        # Populate the optimizer registries without importing optional GUI integrations.
        for namespace in ('d810.optimizers.microcode.instructions', 'd810.optimizers.microcode.flow', 'd810.mba.rules'):
            package = importlib.import_module(namespace)
            for module in pkgutil.walk_packages(package.__path__, namespace + '.'):
                importlib.import_module(module.name)
        from d810.optimizers.microcode.instructions.handler import InstructionOptimizationRule
        from d810.optimizers.microcode.flow.handler import FlowOptimizationRule
        from d810.mba.rules import VerifiableRule
        from d810.mba.backends.ida import adapt_rules
        known_ins = [rule() for rule in InstructionOptimizationRule.registry.values() if not inspect.isabstract(rule)]
        known_ins.extend(adapt_rules(VerifiableRule.instantiate_all()))
        known_blocks = [rule() for rule in FlowOptimizationRule.registry.values() if not inspect.isabstract(rule)]
    else:
        from d810.optimizers.instructions import KNOWN_INS_RULES
        from d810.optimizers.flow import KNOWN_BLK_RULES
        known_ins, known_blocks = KNOWN_INS_RULES, KNOWN_BLK_RULES
    from d810.manager import D810Manager

    config = json.loads((plugin_root / 'd810/conf/default_instruction_only.json').read_text(encoding='utf-8'))
    rule_config = {r['name']: r.get('config', {}) for r in config['ins_rules']
                   if r.get('is_activated', True) and r['name'] != 'ExampleGuessingRule'}
    instruction_rules = []
    log_dir = work / 'd810-logs'
    log_dir.mkdir(exist_ok=True)
    for rule in known_ins:
        if rule.name in rule_config:
            rule.configure(rule_config[rule.name])
            rule.set_log_dir(log_dir if is_ng else str(log_dir))
            instruction_rules.append(rule)
    allowed = {'JumpFixer'}
    if profile == 'control_flow':
        allowed.update({'Unflattener', 'UnflattenerSwitchCase', 'UnflattenerFakeJump'})
    block_rules = []
    for rule in known_blocks:
        if rule.name in allowed:
            rule.configure({})
            rule.set_log_dir(log_dir if is_ng else str(log_dir))
            block_rules.append(rule)
    if not instruction_rules:
        raise RuntimeError('No D-810 instruction rules loaded; incompatible package or profile')
    if is_ng:
        import d810.core.config as configuration
        configuration.DEFAULT_IDA_USER_DIR = work / 'ida-user'
        from d810.manager import D810State
        state = D810State()
        state.load(gui=False)
        state.current_ins_rules = instruction_rules
        state.current_blk_rules = block_rules
        state.manager.log_dir = log_dir
        state.d810_config.set('generate_z3_code', False)
        state.d810_config.set('dump_intermediate_microcode', False)
        state.start_d810()
        manager = state.manager
        if not manager.started:
            raise RuntimeError('D-810-ng manager did not start')
    else:
        manager = D810Manager(str(log_dir))
        manager.configure()
        manager.configure_instruction_optimizer(instruction_rules, generate_z3_code=False, dump_intermediate_microcode=False)
        manager.configure_block_optimizer(block_rules)
        manager.reload()
    return manager, [r.name for r in instruction_rules], [r.name for r in block_rules], is_ng


def run():
    import ida_auto
    import ida_funcs
    import ida_gdl
    import ida_hexrays
    import ida_kernwin
    import ida_nalt
    import ida_xref
    import idautils

    work = Path.cwd()
    request = json.loads((work / 'd810-request.json').read_text(encoding='utf-8'))
    if request['profile'] not in ('instructions', 'control_flow'):
        raise ValueError('Unsupported D-810 profile')
    limit = request.get('max_functions', 80)
    if not isinstance(limit, int) or not 1 <= limit <= 80:
        raise ValueError('Invalid function limit')
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError('The installed Hex-Rays decompiler/license cannot analyze this architecture')
    image_base = ida_nalt.get_imagebase()
    addresses = list(idautils.Functions())
    chosen = addresses[:limit]
    before = {}
    failures = []
    started = time.monotonic()
    for ea in chosen:
        try:
            before[ea] = str(ida_hexrays.decompile(ea, flags=ida_hexrays.DECOMP_NO_CACHE))
        except Exception as error:
            failures.append({'address': hex(ea), 'stage': 'baseline', 'error': str(error)})
    manager, instruction_rules, block_rules, is_ng = create_manager(Path(request['plugin_root']), work, request['profile'], Path(request['dependencies']))
    units, edges = [], []
    changes = 0
    matches_total = 0
    try:
        ida_hexrays.clear_cached_cfuncs()
        for ea in chosen:
            if time.monotonic() - started > 210:
                failures.append({'stage': 'budget', 'error': 'Function analysis time budget reached'})
                break
            function = ida_funcs.get_func(ea)
            if function is None:
                continue
            error = ''
            if is_ng:
                manager.stats.reset()
            try:
                cfunc = ida_hexrays.decompile(ea, flags=ida_hexrays.DECOMP_NO_CACHE)
                if cfunc is None:
                    raise RuntimeError('Hex-Rays returned no pseudocode')
                code = str(cfunc)
            except Exception as failure:
                code, error = '', str(failure)
                failures.append({'address': hex(ea), 'stage': 'd810', 'error': error})
            ins_matches = dict(manager.stats.instruction_rule_usage if is_ng else manager.instruction_optimizer.optimizer_usage_info)
            block_matches = {name: sum(values) for name, values in (manager.stats.cfg_rule_usages if is_ng else manager.block_optimizer.cfg_rules_usage_info).items()}
            matched = sum(ins_matches.values()) + sum(block_matches.values())
            changed = bool(code and ea in before and before[ea] != code and matched > 0)
            changes += int(changed)
            matches_total += matched
            blocks = [{'start': hex(block.start_ea), 'end': hex(block.end_ea - 1),
                       'successors': [{'address': hex(s.start_ea), 'flow_type': 'IDA_FLOW'} for s in block.succs()]}
                      for block in ida_gdl.FlowChart(function)]
            units.append({'key': hex(ea), 'name': ida_funcs.get_func_name(ea), 'path': request['snapshot_path'],
                          'language': 'binary', 'address': hex(ea), 'start_line': 1, 'end_line': max(1, len(code.split('\n'))),
                          'start_byte': 0, 'end_byte': 0, 'code': code, 'quality': 'PARSED' if code else 'FAILED',
                          'metadata': {'kind': 'function', 'image_base': hex(image_base), 'rva': hex(ea - image_base),
                                       'pseudocode_mapping': 'FUNCTION_LEVEL_ONLY', 'basic_blocks': blocks,
                                       'baseline_pseudocode': before.get(ea, ''), 'd810_rule_matches': ins_matches,
                                       'd810_block_patches': block_matches, 'd810_changed': changed, 'decompile_error': error}})
            for item in idautils.FuncItems(ea):
                for reference in idautils.XrefsFrom(item, 0):
                    if reference.type in (ida_xref.fl_CF, ida_xref.fl_CN):
                        target = ida_funcs.get_func(reference.to)
                        target_ea = target.start_ea if target else reference.to
                        edges.append({'source_key': hex(ea), 'target_key': hex(target_ea),
                                      'target_name': ida_funcs.get_func_name(target_ea) or hex(target_ea),
                                      'kind': 'CALL', 'certainty': 'DIRECT', 'line': 0, 'address': hex(item)})
    finally:
        manager.stop()
    exported = {unit['key'] for unit in units}
    for edge in edges:
        if edge['target_key'] not in exported:
            edge['target_key'] = ''
    partial = bool(failures or len(units) < len(addresses))
    warnings = ['D-810 rules cover selected patterns; changed text is not a proof of whole-program semantic equivalence.']
    if partial:
        warnings.append('Some functions failed or exceeded the bounded analysis scope.')
    import d810
    result = {'schema_version': 1, 'units': units, 'edges': edges, 'tools': [], 'warnings': warnings,
              'files': [{'path': request['snapshot_path'], 'language': 'binary', 'status': 'PARTIAL' if partial else 'PARSED',
                         'reason': 'See D-810 limits and function failures' if partial else '', 'unit_count': len(units)}],
              'metadata': {'analysis_engine': 'IDA_HEXRAYS_D810', 'ida_version': ida_kernwin.get_kernel_version(),
                           'd810_variant': 'd810-ng' if is_ng else 'd810', 'd810_version': getattr(d810, '__version__', '0.1'), 'python_version': sys.version.split()[0],
                           'hexrays_version': ida_hexrays.get_hexrays_version(), 'hexrays_initialized': True,
                           'd810_hooks_installed': True, 'd810_profile': request['profile'], 'd810_changed_functions': changes,
                           'd810_rule_matches': matches_total, 'instruction_rules': instruction_rules, 'block_rules': block_rules,
                           'failures': failures, 'total_functions': len(addresses), 'target_executed': False}}
    (work / 'd810-result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    import ida_pro
    try:
        run()
    except Exception:
        Path('d810-error.txt').write_text(traceback.format_exc(), encoding='utf-8')
        ida_pro.qexit(1)
    ida_pro.qexit(0)
