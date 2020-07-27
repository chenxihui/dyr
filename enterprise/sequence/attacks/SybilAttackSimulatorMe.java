package enterprise.sequence.attacks;

import org.jgrapht.UndirectedGraph;
import org.jgrapht.graph.DefaultEdge;

public abstract class SybilAttackSimulatorMe {
	
	public static final String NEW_LINE = System.getProperty("line.separator");

	public abstract void createInitialAttackerSubgraph(int attackerCount, int victimCount);
	public abstract void evolveAttackerSubgraph(int attackerCount, int victimCount, int choice);
	public abstract double currentSuccessProbability(int attackerCount, int victimCount, UndirectedGraph<String, DefaultEdge> graph, UndirectedGraph<String, DefaultEdge> originalGraph); 
	public abstract double updateSuccessProbabilities(int attackerCount, int victimCount, UndirectedGraph<String, DefaultEdge> graph, UndirectedGraph<String, DefaultEdge> originalGraph);
}
