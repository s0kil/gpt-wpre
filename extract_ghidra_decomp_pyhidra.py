#!/usr/bin/env python3

import os
import json
import pyhidra
from tqdm import tqdm
from collections import defaultdict

program_path = "/home/danielsokil/Lab/s0kil/bmminer_NBP1901/bmminer"

# Need to have pyhidra configured in Ghidra, check the docs
# https://github.com/dod-cyber-crime-center/pyhidra

with pyhidra.open_program(program_path) as flat_api:
    program = flat_api.getCurrentProgram()

    function_manager = program.getFunctionManager()
    functions = list(function_manager.getFunctions(True))

    program_function_names = {}
    program_call_graph = defaultdict(list)

    for func in tqdm(functions, desc="Building call graph"):
        # Get the function name
        name = func.getName()
        program_function_names[name] = func
        for calledFunc in func.getCalledFunctions(None):
            if calledFunc.isThunk():
                continue
            calledName = calledFunc.getName()

            if calledName == name:
                continue
            program_call_graph[name].append(calledName)

    program_call_graph = dict(program_call_graph)

    for func in functions:
        name = func.getName()
        if name not in program_call_graph and not func.isThunk():
            program_call_graph[name] = []

    # Decompile all the functions

    from ghidra.app.decompiler import DecompInterface, DecompileOptions

    decompiler = DecompInterface()

    # Pull decompiler options from the current program
    opt = DecompileOptions()
    opt.grabFromProgram(program)
    decompiler.setOptions(opt)

    missing = []
    decompiler.openProgram(program)
    decomps = {}
    for func in tqdm(functions, desc="Decompiling functions"):
        name = func.getName()
        decomp_result = decompiler.decompileFunction(func, 0, None)
        decomp_func = decomp_result.getDecompiledFunction()
        if not decomp_func:
            missing.append(name)
            continue
        decomps[name] = decomp_func.getC()
    decompiler.closeProgram()

    # Save the decompilations
    with open(
        os.path.join(os.path.dirname(program_path), "decompilations.json"),
        "w",
        encoding="UTF-8",
    ) as file:
        out = json.dumps(decomps, sort_keys=True, indent=4)
        file.write(out)
        file.write("\n")

    # Remove missing functions from the call graph
    for func in missing:
        del program_call_graph[func]
        for called in program_call_graph:
            if func in program_call_graph[called]:
                program_call_graph[called].remove(func)
    print(f"Missing {len(missing)} functions:")
    print(missing)

    # Save the call graph
    with open(
        os.path.join(os.path.dirname(program_path), "call_graph.json"),
        "w",
        encoding="UTF-8",
    ) as file:
        out = json.dumps(program_call_graph, sort_keys=True, indent=4)
        file.write(out)
        file.write("\n")
