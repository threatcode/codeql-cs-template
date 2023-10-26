import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph
import DataFlow::PathNode
import DataFlow::PathEdge
import DataFlow::PathScope

// Define a user-controlled source, such as user input
class UserControlledSource extends TaintTracking::Configuration {
  UserControlledSource() {
    this = dataFlow::parameter
  }
}

// Define a sink where the tainted data can cause a security vulnerability
class SecurityVulnerabilitySink extends TaintTracking::Configuration {
  SecurityVulnerabilitySink() {
    exists(Sink s | s.getAControlFlowNode() = this)
  }
}

// Create a data flow path that connects a user-controlled source to a security vulnerability sink
from
  UserControlledSource source,
  DataFlow::PathNode sourceNode,
  SecurityVulnerabilitySink sink,
  DataFlow::PathNode sinkNode,
  DataFlow::PathGraph graph
where
  graph.paths(sourceNode, sinkNode, source, sink)
  and
  sourceNode.asExpr().getASource().getType().(unqualifiedType()).toString() = "string"
  and
  not exists(DataFlow::PathScope scope |
    scope.getNode() = sinkNode
    and
    scope.getASource() = sourceNode
  )
select
  sourceNode,
  sinkNode,
  "Potential SQL Injection vulnerability",
  sinkNode.getALocation()
