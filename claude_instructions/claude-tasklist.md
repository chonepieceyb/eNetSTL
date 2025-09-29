Tips:
    1.Skip step_list taged with finished, finish step_list taged with TODO.
    2.When reading a paper, if the file size is greater than 0.8MB, please split the paper into multiple smaller  files by pages for sequential reading, such as /PaperName/seg1_PaperName.pdf, /PaperName/seg2_PaperName.pdf, etc.

step_list1: all (finished)
    1.Analyze all source code.
    2.Analyze papers in claude_instructions/papers. To prevent the large model from being unable to read the    entire paper at once, the paper can be read in multiple segments.
    3.Explain this project in detail based both on the source code and the paper.
    4.The explanation needs to be detailed and easy to understand, friendly to beginners, and include   necessary supplementary notes on prerequisite knowledge.
    5.Only read the code of the current branch, switching git branches is not allowed.
    6.Write result in claude_instructions/docs/project_explain.md.

step_list2: mm_proxy (finished)
    1.Analyze all source code.
    2.A detailed explanation of the memory proxy mechanism of eNetSTL and writing to claude_instructions/docs/mm_proxy.md.

step_list3: extension (TODO)
    1.Analyze paper SimdNN-BPF.pdf in claude_instructions/papers/. 
    2.Plan to extend a new module under the LKM directory, consistent with the motivation of the paper 'Real-Time Intrusion Detection and Prevention with Neural Network in Kernel using eBPF'. Accelerate neural network inference in eBPF, but implement it using SIMD.
    3.Write out the complete design concept and the expected development framework in claude_instructions/docs/extension-SimdNN-BPF.md.