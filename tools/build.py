# SPDX-License-Identifier: GPL-2.0-only
from build_common import *

def main():
    cfg=json.loads(Path(sys.argv[1]).read_text());out=Path(cfg["out"]).resolve();project=Path(cfg["project"]).resolve();out.mkdir(parents=True,exist_ok=True)
    nt=Path(cfg["nt"]).resolve()/"Source/XPSP1/NT"
    operation=cfg["operation"];start=time.time()
    handler=load(Path(cfg["handler"]),"action_handler")
    if operation=="native":handler.build_native(cfg,out,project,nt)
    elif operation=="boot_support":handler.build_boot(cfg,out,project,nt)
    elif operation in ("minimal_rootfs","rootfs"):handler.build_userspace(cfg,out,project,nt)
    elif operation.endswith("_image"):handler.build(cfg,out,project,nt)
    else:raise RuntimeError("Unknown action "+operation)
    (out/"build-result.json").write_text(json.dumps({"operation":operation,"seconds":time.time()-start,"upstream_commit":(nt.parents[2]/"UPSTREAM_COMMIT").read_text().strip()},indent=2)+"\n")
    print(operation,"finished in",round(time.time()-start,1),"seconds",flush=True)

if __name__=="__main__":main()
