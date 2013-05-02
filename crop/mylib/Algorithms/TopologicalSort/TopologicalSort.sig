signature TopologicalSort =
sig
  datatype ''a result = Cycle of ''a list
                      | Sorted of ''a list
  val sort : ''a Set.t * (''a * ''a) Set.t -> ''a result

end
