from z3 import *

def sesame(value):
    solver = Solver()

    key = BitVec('key', 32)

    constraint = (key ^ value) == 0xdeadc0de

    solver.add(constraint)

    if solver.check() == sat:
        model = solver.model()
        solution_key = model[key].as_long()
        return solution_key
    else:
        return None

value = 0x6b8b4567

solution = sesame(value)
if solution is not None:
    print(f"Solution found: key = 0x{solution:08X}")
else:
    print("No solution found.")
