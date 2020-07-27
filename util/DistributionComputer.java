package util;

import java.util.Map;
import org.jgrapht.UndirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;

public interface DistributionComputer {
	
	Map<Integer, Double> computeDistributionAsProbabilities(SimpleGraph<String, DefaultEdge> graph);
	Map<Integer, Integer> computeDistributionAsCounts(SimpleGraph<String, DefaultEdge> graph);

}
