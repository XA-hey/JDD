package jdd.dataflow;


import jdd.PointToAnalyze.pointer.Pointer;
import jdd.markers.Stage;
import jdd.tranModel.Rules.RuleUtils;
import jdd.tranModel.TranUtil;
import jdd.tranModel.TransformableNode;
import ext.cg.CG;
import jdd.container.BasicDataContainer;
import jdd.container.FragmentsContainer;
import jdd.dataflow.node.MethodDescriptor;
import jdd.dataflow.node.SourceNode;
import jdd.dataflow.node.UndeterminedFieldNode;
import jdd.gadgets.collection.node.ClassNode;
import jdd.gadgets.collection.node.GadgetInfoRecord;
import jdd.gadgets.collection.node.GadgetNode;
import jdd.gadgets.unit.Fragment;
import jdd.util.Pair;
import lombok.extern.slf4j.Slf4j;

import soot.*;
import jdd.util.ClassRelationshipUtils;
import ext.util.StaticAnalyzeUtils.Parameter;
import jdd.util.Utils;

import java.io.IOException;
import java.util.*;

import static jdd.dataflow.DataFlowAnalysisUtils.*;
import static jdd.detetor.SearchUtils.initDealBeforeSearching;
import static jdd.util.ClassRelationshipUtils.containsInCallStack;


@Slf4j
public class DataflowDetect {
    /**
     *  收集sootMethod中涉及到的fields
     * @param sootMethod
     * @param usedFields
     */
    public void collectFields(SootMethod sootMethod,
                              HashSet<SourceNode> usedFields,
                              LinkedList<SootMethod> callStack) throws IOException {
        MethodDescriptor descriptor = getMethodDescriptor(sootMethod);
        if (descriptor == null) return;

        // 更新调用该method的方法到该方法的信息, ;过程间分析
        updateInterInfos(descriptor);

        List<TransformableNode> topologicalOrder = TranUtil.getTopologicalOrderedTNodesFromCFG(descriptor.cfg);
        for (TransformableNode tfNode: topologicalOrder){
            // 记录该语句中相关的fields, 并记录使用信息
            HashMap<SourceNode, HashSet<Pair<String,Integer>>> ret = extractUsedFields(tfNode, descriptor);
            for (SourceNode sourceNode: ret.keySet()){
                if (sourceNode.classOfField.equals(descriptor.getCurrentClass()))
                    usedFields.add(sourceNode);
            }


            checkTransformable(tfNode,descriptor,callStack);

            if (tfNode.containsInvoke() & callStack.size() <= BasicDataContainer.stackLenLimitForFieldsCollection){

                if (continueCheck(tfNode, descriptor)) {
                    HashMap<Integer, Pointer> inputCallFrame = getMethodBaseParamInfo(tfNode, descriptor);
                    HashSet<SootMethod> invokedMethods = getInvokedMethods(tfNode, descriptor);
                    if (invokedMethods.size() > 10) {
                        callStack.add(null);
                        return;
                    };

                    for (SootMethod invokedMethod: invokedMethods) {
                        MethodDescriptor invokedDescriptor = flowInvokedMethod(descriptor, invokedMethod, inputCallFrame, callStack, tfNode);
                        if (invokedDescriptor == null | sootMethod.equals(invokedMethod)) {
                            callStack.add(null);
                            continue;
                        }
                        collectFields(invokedMethod, usedFields, callStack);
                        outInvokedMethod(invokedDescriptor, descriptor, tfNode, callStack);
                    }
                }else {
                    callStack.add(null);
                }
            }
        }

        updateAfterAnalysisMtd(descriptor);
    }


    public void detectFragment(MethodDescriptor descriptor, LinkedList<SootMethod> callStack) throws IOException {
        SootMethod sootMethod = getMethodDescriptor(descriptor);
        if (sootMethod == null)
            return;
        if (ClassRelationshipUtils.isProxyMethod(sootMethod)){
            log.info("DEBUG");
        }

        // 更新调用该method的方法到该方法的信息, ;过程间分析
        updateInterInfos(descriptor);

        List<TransformableNode> topologicalOrder = TranUtil.getTopologicalOrderedTNodesFromCFG(descriptor.cfg);
        for (TransformableNode tfNode: topologicalOrder){
            if (!checkTransformable(tfNode,descriptor,callStack)) continue;

            if (callStack.size() <= BasicDataContainer.stackLenLimitNum){
                recordEqualsFieldInEqualsMtd(tfNode, descriptor);

                // 进行污点检查, 判断是否有需要继续跟进invoked method进行污点分析
                if(!continueCheck(tfNode, descriptor)){ continue; }

                // 记录方法调用中this指针信息和参数的指针信息
                HashMap<Integer, Pointer> inputCallFrame = getMethodBaseParamInfo(tfNode, descriptor);
                HashSet<SootMethod> invokedMethods = generateFragmentsOrInvokedMethods(descriptor, tfNode, inputCallFrame, callStack);

                for (SootMethod invokedMethod: invokedMethods) {
                    if (BasicDataContainer.blackList.contains(invokedMethod.getSignature())
                            || isDupInvokedMethodInFragment(invokedMethod, callStack))
                        continue;

                    MethodDescriptor calleeDescriptor = flowInvokedMethod(descriptor, invokedMethod, inputCallFrame, callStack, tfNode);
                    if (calleeDescriptor == null)
                        continue;

                    detectFragment(calleeDescriptor, callStack);
                    outInvokedMethod(calleeDescriptor, descriptor, tfNode, callStack);
                }
            }
        }

        updateAfterAnalysisMtd(descriptor);
    }


    public HashSet<Fragment> linkFreeStateFragments(Fragment freeStateFragment){
        HashSet<Fragment> newSinkFragments = new HashSet<>();
        HashSet<Fragment> linkableSinkFragments = FragmentsContainer.getLinkableSinkFragments(freeStateFragment);
        for (Fragment sinkFragment: linkableSinkFragments){
            if (sinkFragment.type.equals(Fragment.FRAGMENT_TYPE.REFLECTION)){

            }else {
                Fragment newSinkFragment = new Fragment(freeStateFragment, sinkFragment);
                if (newSinkFragment.isFlag())
                    newSinkFragments.add(newSinkFragment);
            }
        }

        return newSinkFragments;
    }


    public HashSet<Fragment> linkSourceFragments(Fragment sourceFragment){ // bottom-up 链接fragment
        HashSet<Fragment> newSinkFragments = new HashSet<>();
        if (sourceFragment.sinkType != null){
            newSinkFragments.add(sourceFragment);
            return newSinkFragments;
        }

        HashSet<Fragment> linkableSinkFragments = FragmentsContainer.getLinkableSinkFragments(sourceFragment);
        RuleUtils.heuristicEqChainLink(sourceFragment, linkableSinkFragments);
        for (Fragment sinkFragment: linkableSinkFragments){
            if (!RuleUtils.heuristicGadgetChainLink(sourceFragment, null))
                continue;
            if (sinkFragment.type.equals(Fragment.FRAGMENT_TYPE.REFLECTION)){

            }else {
                Fragment newSinkFragment = new Fragment(sourceFragment, sinkFragment);
                if (newSinkFragment.isFlag())
                    newSinkFragments.add(newSinkFragment);
            }
        }

        return newSinkFragments;
    }


    public void constructFieldsTaintGraph(SootMethod sootMethod,
                                          LinkedList<SootMethod> callStack,
                                          HashSet<UndeterminedFieldNode> undeterminedFieldNodes) throws IOException {
        MethodDescriptor descriptor = getMethodDescriptor(sootMethod);
        if (descriptor == null) return;

        updateInterInfos(descriptor);
        List<TransformableNode> topologicalOrder = TranUtil.getTopologicalOrderedTNodesFromCFG(descriptor.cfg);
        for (TransformableNode tfNode: topologicalOrder){
            if (!checkTransformable(tfNode,descriptor,callStack)) continue;

            if (callStack.size() <= BasicDataContainer.stackLenLimitNum){
                if(!continueCheck(tfNode, descriptor)){ continue; }

                HashMap<Integer, Pointer> inputCallFrame = getMethodBaseParamInfo(tfNode, descriptor);
                HashSet<SootMethod> invokedMethods = generateFragmentsOrInvokedMethods(descriptor, tfNode, inputCallFrame, callStack);

                for (SootMethod invokedMethod: invokedMethods) {
                    MethodDescriptor calleeDescriptor = flowInvokedMethod(descriptor, invokedMethod, inputCallFrame, callStack, tfNode);
                    if (calleeDescriptor == null)
                        continue;

                    constructFieldsTaintGraph(invokedMethod, callStack, undeterminedFieldNodes);
                    outInvokedMethod(calleeDescriptor, descriptor, tfNode, callStack);
                }
            }
        }
    }

    public void inferGadgetInfosOfWholeLife(SootMethod sootMethod,
                                             GadgetInfoRecord gadgetInfoRecord,
                                             LinkedList<SootMethod> callStack) throws IOException {
        BasicDataContainer.stage = Stage.IOCD_GENERATING;
        inferGadgetInfos(sootMethod,gadgetInfoRecord,callStack);
        if (gadgetInfoRecord.flag){
            inferSupplementGadgetInfos(gadgetInfoRecord);
        }
        BasicDataContainer.getOrCreateDescriptor(gadgetInfoRecord.gadgets.get(0)).isEntry = false;
    }


    public void  inferGadgetInfos(SootMethod sootMethod,
                                 GadgetInfoRecord gadgetInfoRecord,
                                 LinkedList<SootMethod> callStack) throws IOException {
        MethodDescriptor descriptor = getMethodDescriptor(sootMethod);
        if (descriptor == null) return;


        boolean inImplicitClassFlag = gadgetInfoRecord.inImplicitClass(callStack, sootMethod) & !gadgetInfoRecord.flag;
        gadgetInfoRecord.updateCurrentClass(descriptor, callStack, inImplicitClassFlag);
        gadgetInfoRecord.inImplicitClassFlag = inImplicitClassFlag;


        updateInterInfos(descriptor);


        List<TransformableNode> topologicalOrder = TranUtil.getTopologicalOrderedTNodesFromCFG(descriptor.cfg);

        for (TransformableNode tfNode: topologicalOrder){

            gadgetInfoRecord.recordForward(tfNode, descriptor);

            checkTransformable(tfNode,descriptor,callStack);

            descriptor.sourcesTaintGraph.updateSourceUnFound(callStack,descriptor);

            if (tfNode.containsInvoke() &
                    Utils.getCallStacksDeviation(callStack, gadgetInfoRecord.gadgets) < BasicDataContainer.stackDeviationLimit){
                if(!continueCheck(tfNode, descriptor)) {
                    inferExtraInfosOfGadgetChain(callStack, gadgetInfoRecord,
                            descriptor, tfNode, inImplicitClassFlag);
                    continue;
                }

                boolean tmpInImplicitClassFlag = inImplicitClassFlag & !containsInCallStack(gadgetInfoRecord.gadgets, tfNode.getUnitInvokeExpr().getMethod());
                gadgetInfoRecord.inImplicitClassFlag = tmpInImplicitClassFlag;

                HashMap<Integer, Pointer> inputCallFrame = getMethodBaseParamInfo(tfNode, descriptor);
                HashSet<SootMethod> invokedMethods = getInvokedMethods(tfNode, inputCallFrame, callStack, gadgetInfoRecord);
                tmpInImplicitClassFlag = gadgetInfoRecord.inImplicitClassFlag;

                for (SootMethod invokedMethod: invokedMethods) {
                    MethodDescriptor calleeDescriptor = flowInvokedMethod(descriptor, invokedMethod, inputCallFrame, callStack, tfNode);
                    if (calleeDescriptor == null) {
                        inferExtraInfosOfGadgetChain(callStack, gadgetInfoRecord,
                                descriptor, tfNode, inImplicitClassFlag);
                        continue;
                    }

                    ClassNode conClassNode = null;
                    if (!FragmentsContainer.isSinkMethod(invokedMethod)){
                        if (Utils.isSubList(callStack,gadgetInfoRecord.gadgets)){
                            inferInfosOnGadgetChain(gadgetInfoRecord, callStack, tfNode, calleeDescriptor, descriptor);
                        }
                        else if (tmpInImplicitClassFlag){
                            conClassNode = inferInfosOutOfGadgetChain(gadgetInfoRecord, callStack,tfNode,calleeDescriptor,descriptor);
                        }

                        inferGadgetInfos(invokedMethod, gadgetInfoRecord, callStack);
                        outInvokedMethod(calleeDescriptor, descriptor, tfNode, conClassNode, gadgetInfoRecord, callStack);
                    }
                    else if (gadgetInfoRecord.gadgets.contains(invokedMethod)
                            & Utils.isSubList(callStack, gadgetInfoRecord.gadgets)){
                        GadgetNode gadgetNode = gadgetInfoRecord.getGadgetNode(sootMethod);
                        gadgetNode.recordDominatorConditions(tfNode, gadgetInfoRecord, descriptor);
                    }

                    gadgetInfoRecord.updateCurrentClass(descriptor, callStack, inImplicitClassFlag);
                }
            }

            inferExtraInfosOfGadgetChain(callStack, gadgetInfoRecord,
                    descriptor, tfNode, inImplicitClassFlag);
        }

        if (Utils.isSubList(callStack, gadgetInfoRecord.gadgets)){
            GadgetNode gadgetNode = gadgetInfoRecord.getGadgetNode(sootMethod);
            if (gadgetNode != null)
                gadgetNode.markConditionType();
        }

        updateAfterAnalysisMtd(descriptor);
    }

    public void inferSupplementGadgetInfos(GadgetInfoRecord gadgetInfoRecord) throws IOException {
        BasicDataContainer.stage = Stage.IOCD_SUPPLEMENT_INFER;
        HashSet<String> supplementSubMethodSigs = new HashSet<>(FragmentsContainer.protocolCheckRule.entryMethods);
        supplementSubMethodSigs.add("void writeObject(java.io.ObjectOutputStream)");

        for (SootClass sootClass: gadgetInfoRecord.classFieldsGraph.keySet()){
            HashSet<SootMethod> methodsList = ClassRelationshipUtils.getMethodsOfClass(sootClass, supplementSubMethodSigs);


            ClassNode curClassNode = gadgetInfoRecord.classFieldsGraph.get(sootClass);
            gadgetInfoRecord.implicitGadgetNodesMap.put(sootClass, new LinkedHashMap<>());
            for (SootMethod entryMethod : methodsList){
                if (gadgetInfoRecord.gadgets.contains(entryMethod))
                    continue;

                MethodDescriptor descriptor = initDealBeforeSearching(entryMethod, null);
                LinkedList<SootMethod> callStack = new LinkedList<>();
                callStack.add(entryMethod);

                GadgetNode newGadgetNode = new GadgetNode(entryMethod, curClassNode.sootClass);
                curClassNode.addGadgetNode(newGadgetNode);

                inferSupplementGadgetInfos(entryMethod, gadgetInfoRecord, callStack);
                descriptor.isEntry = false;
            }
        }
        RuleUtils.supplementDependenceHC(gadgetInfoRecord);
    }

    public void inferSupplementGadgetInfos(SootMethod sootMethod,
                                           GadgetInfoRecord gadgetInfoRecord,
                                           LinkedList<SootMethod> callStack) throws IOException {
        MethodDescriptor descriptor = getMethodDescriptor(sootMethod);
        if (descriptor == null)
            return;

        boolean inImplicitClassFlag = gadgetInfoRecord.getLastClassNode(callStack) != null & !sootMethod.isStatic();
        gadgetInfoRecord.inImplicitClassFlag = inImplicitClassFlag;
        gadgetInfoRecord.updateCurrentClass(descriptor, callStack, inImplicitClassFlag);

        updateInterInfos(descriptor);
        List<TransformableNode> topologicalOrder = TranUtil.getTopologicalOrderedTNodesFromCFG(descriptor.cfg);
        for (TransformableNode tfNode: topologicalOrder){
            gadgetInfoRecord.recordForward(tfNode, descriptor);
            checkTransformable(tfNode, descriptor, callStack);

            if (tfNode.containsInvoke() &
                    callStack.size() <= BasicDataContainer.stackDeviationLimit){
                if(!continueCheck(tfNode, descriptor)) {
                    tfNode.forwardExtraInferCheck(descriptor, gadgetInfoRecord);
                    continue;
                }

                HashMap<Integer, Pointer> inputCallFrame = getMethodBaseParamInfo(tfNode, descriptor);
                HashSet<SootMethod> invokedMethods = getInvokedMethods(tfNode, inputCallFrame, callStack, gadgetInfoRecord);

                ClassNode conClassNode = null;

                for (SootMethod invokedMethod: invokedMethods) {
                    MethodDescriptor calleeDescriptor = flowInvokedMethod(descriptor, invokedMethod, inputCallFrame, callStack, tfNode);
                    if (calleeDescriptor == null) {
                        tfNode.forwardExtraInferCheck(descriptor, gadgetInfoRecord);
                        continue;
                    }

                    if (!FragmentsContainer.isSinkMethod(invokedMethod)){
                        if (inImplicitClassFlag){
                            conClassNode = inferInfosOutOfGadgetChain(gadgetInfoRecord, callStack,tfNode,calleeDescriptor,descriptor);
                        }
                        // 判断是否继续跟进
                        if (!continueInferSupplementInfos(invokedMethod, gadgetInfoRecord)) {
                            callStack.remove(invokedMethod);
                            continue;
                        }

                        inferInfosOutOfGadgetChain(gadgetInfoRecord, callStack, tfNode, calleeDescriptor, descriptor);

                        inferSupplementGadgetInfos(invokedMethod, gadgetInfoRecord, callStack);
                        outInvokedMethod(calleeDescriptor, descriptor, tfNode,
                                conClassNode, gadgetInfoRecord, callStack);
                    }
//                    // 调用后清理信息
//                    sanitizerAfterMethodInvoke(conClassNode, calleeDescriptor);

                    gadgetInfoRecord.updateCurrentClass(descriptor, callStack, inImplicitClassFlag);
                }
            }
            inferExtraInfosOfGadgetChain(callStack, gadgetInfoRecord,
                    descriptor, tfNode, false);
        }
        updateAfterAnalysisMtd(descriptor);
    }
}
