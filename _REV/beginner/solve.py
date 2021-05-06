import angr
p = angr.Project('./a.out')
sim = p.factory.simgr()
sim.explore(find = lambda output: b'SUCCESS' in output.posix.dumps(1))
print(sim.found[0].posix.dumps(0))