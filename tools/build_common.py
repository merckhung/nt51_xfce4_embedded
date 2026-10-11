# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import importlib.util,json,os,shutil,subprocess,sys,time,hashlib,tempfile,stat

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path); mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod


def run(args,cwd=None,env=None):
    result=subprocess.run([str(a) for a in args],cwd=cwd,env=env,capture_output=True,text=True,errors='replace')
    if result.returncode:
        raise RuntimeError('Command failed: '+str(args)+'\n'+result.stdout+'\n'+result.stderr)
    return result.stdout+result.stderr


def tool(name):
    root=os.environ.get('LLVM_ROOT')
    found=str(Path(root)/'bin'/(name+'.exe')) if root else shutil.which(name)
    if not found or not Path(found).is_file(): raise RuntimeError('Required tool missing: '+name+' (set LLVM_ROOT or PATH)')
    return found


def copytree(src,dst):
    shutil.copytree(src,dst,dirs_exist_ok=True,ignore=shutil.ignore_patterns('BUILD.bazel','RELEASE','__pycache__'))


def remove_owned(path,owner):
    target=Path(path).resolve();root=Path(owner).resolve()
    if target==root or not target.is_relative_to(root):raise RuntimeError('Refusing cleanup outside owned scratch directory: '+str(target))
    def writable_retry(function,name,error):
        os.chmod(name,stat.S_IWRITE);function(name)
    if target.exists():shutil.rmtree(target,onexc=writable_retry)


def compile_many(sources,cc,flags,out):
    out.mkdir(parents=True,exist_ok=True)
    def compile_one(item):
        i,src=item;obj=out/(str(i)+'_'+src.stem+'.o');run([cc,*flags,'-c',src,'-o',obj]);return obj
    with ThreadPoolExecutor(max_workers=min(os.cpu_count() or 4,16)) as pool:
        objects=list(pool.map(compile_one,enumerate(sources)))
    print('Compiled',len(objects),'sources',flush=True)
    return objects


def archive(objects,path):
    rsp=path.with_suffix('.rsp');rsp.write_text('\n'.join('"'+str(o)+'"' for o in objects)+'\n')
    run([tool('llvm-ar'),'rcs',path,'@'+str(rsp)])


