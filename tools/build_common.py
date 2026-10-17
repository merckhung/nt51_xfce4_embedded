# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import importlib.util,json,os,shutil,subprocess,sys,time,hashlib,tempfile,stat

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path); mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod


def run(args,cwd=None,env=None):
    cmd=[str(a) for a in args]
    if os.name!='nt' and cmd and cmd[0].lower().endswith('.exe'):
        linker=Path(cmd[0]).name.lower()=='link.exe'
        runner=(os.environ.get('WINE') or shutil.which('wine')) if linker else (os.environ.get('WIBO') or shutil.which('wibo'))
        if not runner: raise RuntimeError('Required tool missing: '+('wine' if linker else 'wibo')+' (set WINE/WIBO or PATH)')
        base=str(cwd or os.getcwd())
        prefixes=('/I','/Fo','/Fp','/Tc','/Tp','/OUT:','/DEF:','/IMPLIB:','/PDB:','/MAP:')
        converted=[runner,cmd[0]]
        for a in cmd[1:]:
            matched=False
            for p in prefixes:
                if a.startswith(p) and a[len(p):].startswith('/'):
                    converted.append(p+os.path.relpath(a[len(p):],base))
                    matched=True
                    break
            if not matched:
                if a.startswith('/') and '/' in a[1:] and (Path(a).exists() or Path(a).parent.exists()):
                    converted.append(os.path.relpath(a,base))
                else:
                    converted.append(a)
        cmd=converted
        env=(env or os.environ).copy()
        env['PATH']=str(Path(args[0]).parent)+':'+env.get('PATH','').replace(';',':')
        if linker:
            env['WINEDEBUG']='-all'
            env.setdefault('WINEPREFIX',str(Path.home()/'.cache/nt51-wine-prefixes/manual'))
    # Wine's service processes may inherit stdout and outlive the compiler.
    # A file lets us wait for the tool itself without waiting for pipe EOF.
    with tempfile.TemporaryFile(mode='w+',encoding='utf-8',errors='replace') as stream:
        result=subprocess.run(cmd,cwd=cwd,env=env,stdout=stream,stderr=subprocess.STDOUT)
        stream.seek(0);output=stream.read()
    if result.returncode:
        raise RuntimeError('Command failed: '+str(cmd)+'\n'+output)
    return output


def tool(name):
    root=os.environ.get('LLVM_ROOT')
    suffix='.exe' if os.name=='nt' else ''
    found=str(Path(root)/'bin'/(name+suffix)) if root else shutil.which(name)
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


