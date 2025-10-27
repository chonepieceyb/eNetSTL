TODO: this file implement interactive generation of skeleton, by using other skeleton generation scripts.

param:
    subproject: name of the subproject, no default value
    prog_type: [XDP] (currently only support XDP)
    feature_lists: list of features to be included, e.g., [kfunc] (currently only support kfunc)
    author_name: author name, no default
    version: version number, no default

generated_files:

- bpf_kern_file: PROJECT_ROOT/src/bpf_kern/$subproject/$subproject.bpf.c
- bpf_user_files: PROJECT_ROOT/src/c/$subproject/$subproject_user.c and              PROJECT_ROOT/src/c/$subproject/$test_subproject_user.c
- LKM_files (if applicable): PROJECT_ROOT/src/LKMs/$subproject/module.c and PROJECT_ROOT/src/LKMs/$subproject/Makefile

### for bpf_kern_file
    scripts_list = []
    scripts_list.append("gen_bpf_common_header.spec.md")
    if prog_type == XDP:
        scripts_list.append("gen_xdp_skel.spec.md")
    else: 
        not support

    if 'kfunc' in feature_lists: 
        scripts_list.append("gen_kfunc_skel.spec.md")

    generate code using scripts in scripts_list, merge code snippets into one file.
        
### for bpf_user_files
    scripts_list = []
    test_scripts_list = []
    if prog_type == XDP:
        scripts_list.append("gen_xdp_skel.spec.md")
        test_scripts_list.append("gen_xdp_testing_skel.spec.md")
    else:
        not support

    generate $subproject_user.c  code using scripts in scripts_list, merge code snippets into one file.
    generate test_$subproject_user.c code using scripts in test_scripts_list, merge code snippets into one file.

### for LKM_files
    if 'kfunc' in feature_lists:
        generate module.c and Makefile using gen_kfunc_skel.spec.md
    else:
        not support


### Author and version 

add author and version info to all generated files.