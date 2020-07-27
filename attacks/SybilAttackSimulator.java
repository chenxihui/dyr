package attacks;

import org.jgrapht.UndirectedGraph;
import org.jgrapht.graph.DefaultEdge;

public abstract class SybilAttackSimulator {
	
	public static final String NEW_LINE = System.getProperty("line.separator");

	public abstract void simulateAttackerSubgraphCreation(UndirectedGraph<String, DefaultEdge> graph, int attackerCount, int victimCount);
	public abstract double successProbability(int attackerCount, int victimCount, UndirectedGraph<String, DefaultEdge> graph, UndirectedGraph<String, DefaultEdge> originalGraph);

}
