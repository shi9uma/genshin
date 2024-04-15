source /home/app/pwnenv/pwndbg/repo/gdbinit.py

# splitmind
source /home/app/pwnenv/pwndbg/plugins/splitmind/gdbinit.py
python
import splitmind
(splitmind.Mind()
  .below(display="backtrace")
  .right(display="stack")
  .right(display="regs")
  .right(of="main", display="disasm")
  .show("legend", on="disasm")
).build()
end
