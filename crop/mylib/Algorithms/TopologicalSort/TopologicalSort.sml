structure TopologicalSort :> TopologicalSort =
struct
datatype ''a result = Cycle of ''a list
                    | Sorted of ''a list

fun sort graph =
    let
      exception Cyc of ''a list
      (* visited nodes -> graph -> node -> (node list, rest of graph) *)
      fun one seen (graph as (ns, es)) n =
          if Set.member seen n then
            raise Cyc [n]
          else
            if Set.member ns n then
              let
                val (es, es') = Set.partition (fn (f, _) => f = n) es
                val (ns, graph) = many (Set.insert seen n) (Set.delete ns n, es') (Set.map #2 es)
              in
                (n :: ns, graph)
              end handle Cyc ns => raise Cyc (n :: ns)
            else
              (nil, graph)

      and many seen graph ns =
          let
            val (n, ns) = Set.split ns
            val (ns', graph') = one seen graph n
            val (ns'', graph'') = many seen graph' ns
          in
            (ns' @ ns'', graph'')
          end handle Empty => (nil, graph)

      fun loop (graph as (ns, _)) =
          let
            val (ns, graph) = one Set.empty graph (Set.some ns)
          in
            loop graph @ ns
          end handle Empty => nil
    in
      Sorted (loop graph) handle Cyc ns => Cycle ns
    end

end
