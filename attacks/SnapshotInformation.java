package attacks;

import java.util.List;

import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;

import enterprise.sequence.generators.Utils;

public class SnapshotInformation {
	
	private SimpleGraph<String, DefaultEdge> graph;
	private SimpleGraph<String, DefaultEdge> noisygraph;
	private List<String> victimList;
	private List<Integer> sybilList;
	private List<String[]> candidateAttackersList;
	
	public SnapshotInformation(SimpleGraph<String, DefaultEdge> graph, 
			SimpleGraph<String, DefaultEdge> noisygraph,
			List<String> victimList, List<Integer> sybilList, List<String[]> candidateAttackersList) {
		this.graph =Utils.cloneGraph(graph);
		this.victimList = victimList;
		this.sybilList = sybilList;
		this.candidateAttackersList = candidateAttackersList;
		this.setNoisyGraph(noisygraph);
	}

	public SimpleGraph<String, DefaultEdge> getGraph() {
		return graph;
	}

	public void setGraph(SimpleGraph<String, DefaultEdge> graph) {
		this.graph = graph;
	}

	public List<String> getVictimList() {
		return victimList;
	}

	public void setVictimList(List<String> victimList) {
		this.victimList = victimList;
	}

	public List<String[]> getCandidateAttackersList() {
		return candidateAttackersList;
	}

	public void setCandidateAttackersList(List<String[]> candidateAttackersList) {
		this.candidateAttackersList = candidateAttackersList;
	}

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return graph + " - " + victimList + " - " + candidateAttackersList;
	}

	public SimpleGraph<String, DefaultEdge> getNoisyGraph() {
		return noisygraph;
	}

	public void setNoisyGraph(SimpleGraph<String, DefaultEdge> noisygraph) {
		this.noisygraph = noisygraph;
	}

	public List<Integer> getSybilList() {
		return sybilList;
	}

	public void setSybilList(List<Integer> sybilList) {
		this.sybilList = sybilList;
	}
}
