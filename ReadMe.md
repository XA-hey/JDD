## JDD: Efficient Detection of Java Deserialization Gadget Chains via Bottom-up Gadget Search and Dataflow-aided Payload Construction
### Publication
Efficient Detection of Java Deserialization Gadget Chains via Bottom-up Gadget Search and Dataflow-aided Payload Construction

B Chen, L Zhang, X Huang, Y Cao, K Lian, Y Zhang, M Yang

IEEE Symposium on Security and Privacy (SP), 2024

### Runtime Environment
JDK 8

Dependencies: See `pom.xml` for specific dependencies

### How to use
`git clone https://github.com/BofeiC/JDD.git`

run `runner/SearchGadgetChains.main`

### Why create this repo
当我使用原仓库代码的时候，将代码导入IDEA之后在使用上发生了一些问题，导致IDEA没有办法正常的识别入口的Main类，同时在Windows环境下使用也会有一定的目录问题（原论文试验环境是Ubuntu）。
于是我在原始仓库代码上进行了目录重构，改了一行处理jdk目录的源码，现在的代码可以直接clone到本地，且可以使用IDEA打开并运行（Windows环境下）。

后续也许会基于该项目做拓展开发。

//English Vserse

When I used the code from the original repository and imported it into IDEA, I encountered some issues that prevented IDEA from properly recognizing the Main class as the entry point. Additionally, there were certain directory problems when using it in a Windows environment (the original experimental environment was Ubuntu).
As a result, I performed directory restructuring on the original repository code and made a modification to the source code for handling the JDK directory. Now, the updated code can be cloned directly to the local machine and can be opened and run using IDEA (in a Windows environment).

There might be future plans to extend and develop upon this project.
### Configuration item description
- inputPath: test project path
- outputDir: output directory. E.g. IOCDs
- outPutDirName：Name of the folder where IOCDs are stored
- prioritizedGadgetChainLimit: Output N highest prioritized gadget chains
- protocol: currently supports jdk, hessian, json (e.g. jackson, ...).
  - needSerializable: please adjust them together with `protocol`.
    - jdk: needSerializable = true
    - hessian: needSerializable = false or true
    - json: needSerializable = false or true

- sinkRules:
  - available options: classLoad,invoke,jndi,exec,secondDes,custom,file
    - A version that facilitates custom additions and modifications may come online later
    - Some sinks (in custom) that have not been added/tested after refactoring

### Disclaimer
JDD is developed solely for academic research and to advance defensive techniques. It is not intended for unauthorized system attacks.
The developers disclaim any liability for misuse of the software. Please use it responsibly.

The use of JDD for illegal attacks or profit is prohibited.

### Citation
If you use JDD or some of our code logic, or some of the interesting cases found by JDD, please cite our paper as follows:
```
@inproceedings{chen2024efficient,
  title={Efficient Detection of Java Deserialization Gadget Chains via Bottom-up Gadget Search and Dataflow-aided Payload Construction},
  author={Chen, Bofei and Zhang, Lei and Huang, Xinyou and Cao, Yinzhi and Lian, Keke and Zhang, Yuan and Yang, Min},
  booktitle={2024 IEEE Symposium on Security and Privacy (SP)},
  pages={150--150},
  year={2024},
  organization={IEEE Computer Society}
}
```

### Supported Deserialization Protocols
- JDK
- Hessian(e.g. native hessian, sofa-hessian, hessian-lite...)
- Json (use this protocol pattern to detect fragments linked after `Method.invoke`)
- or similar protocols

Some of the fragments detected by JDD can be generalized across different deserialization protocols, e.g., we used JDD to detect a number of exploitable gadget chains in protocols outside the scope of the paper and obtained some new CVEs.

We've recently refactored JDD, resulting in improved performance in some applications. However, some features remain unstable, and we are actively working on fixing them.

### Details
See more details in original repository.

https://github.com/fdu-sec/JDD
