package attacks;

import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;

import org.jgrapht.Graph;
import org.jgrapht.UndirectedGraph;
import org.jgrapht.graph.DefaultEdge;

import enterprise.sequence.attacks.SequenceOriginalWalkBasedAttackSimulator;
import enterprise.sequence.generators.BarabasiAlbertSequenceGenerator;
import net.vivin.GenericTreeNode;

public class OriginalWalkBasedAttackSimulator extends SybilAttackSimulator {
	
	@Override
	public void simulateAttackerSubgraphCreation(UndirectedGraph<String, DefaultEdge> graph, int attackerCount, int victimCount) {
		
		/* The graph is assumed to satisfy all requirements, notably vertices being labeled from attackerCount on, 
		 * and connectivity if required
		 */
		
		SecureRandom random = new SecureRandom();
			
		if (victimCount == 0)
			victimCount = 1;
		
		if (attackerCount + victimCount > graph.vertexSet().size())
			victimCount = graph.vertexSet().size() - attackerCount;
		
		for (int j = 0; j < attackerCount; j++)
			graph.addVertex(j+"");
		
		Hashtable<String, String> fingerprints = new Hashtable<>();
		for (int j = attackerCount; j < attackerCount + victimCount; j++) {
			String fingerprint = null;
			do {
				fingerprint = Integer.toBinaryString(random.nextInt((int)Math.pow(2, attackerCount)-1) + 1);
				while (fingerprint.length() < attackerCount)
					fingerprint = "0" + fingerprint;
			} while (fingerprints.containsKey(fingerprint));
			
			fingerprints.put(fingerprint, fingerprint);
			
			for (int k = 0; k < fingerprint.length(); k++) {
				if (fingerprint.charAt(k) == '1'){
					graph.addEdge(j+"", (k + attackerCount - fingerprint.length())+"");
				}
			}
		}
		
		if (attackerCount > 1) {
			for (int k = 0; k < attackerCount - 1; k++) {
				graph.addEdge(k+"", (k+1)+"");
			}
		}				
		
		for (int k = 0; k < attackerCount - 2; k++) {
			for (int l = k + 2; l < attackerCount; l++) {
				if (random.nextBoolean() && !graph.containsEdge(k+"", l+"")) {
					graph.addEdge(k+"", l+"");
				}
			}
		}	
	}
	
	// Code taken from Rolando's old Statistics class
	@Override
	public double successProbability(int attackerCount, int victimCount, UndirectedGraph<String, DefaultEdge> graph, UndirectedGraph<String, DefaultEdge> originalGraph) {

		int[] sybilVertexDegrees = new int[attackerCount];
		boolean[][] sybilVertexLinks = new boolean[attackerCount][attackerCount];
		
		for (int i = 0; i < attackerCount; i++) {   // Attackers are assumed to be the first attackerCount vertices in the graph, because of the manner in which the attack was simulated 
			sybilVertexDegrees[i] = originalGraph.degreeOf(i+"");
		}
		
		for (int i = 0; i < attackerCount; i++){
			for (int j = 0; j < attackerCount; j++){
				if (originalGraph.containsEdge(i+"", j+""))
					sybilVertexLinks[i][j] = true;
				else 
					sybilVertexLinks[i][j] = false;
			}
		}
		
		List<String[]> candidates = getPotentialAttackerCandidates(sybilVertexDegrees, sybilVertexLinks, graph);  
		
		if (candidates.isEmpty()) 
			return 0;
		
		/*Trujillo- Feb 4, 2016
		 * Now, for every victim, we obtain the original fingerprint and look 
		 * for the subset S of vertices with the same fingerprint.
		 * 	- If the subset is empty, then the success probability is 0
		 * 	- If the subset is not empty, but the original victim is not in S, 
		 * 		then again the probability of success is 0 
		 * 	- Otherwise the probability of success is 1/|S|*/   
		
		double sumPartialSuccessProbs = 0;
		for (String[] candidate : candidates) {
			double successProbForCandidate = 1d;
			for (int victim = attackerCount; victim < attackerCount + victimCount; victim++) {
				
				/*Trujillo- Feb 9, 2016
				 * We first obtain the original fingerprint*/
				
				String originalFingerprint = "";
				for (int i = 0; i < attackerCount; i++) {
					if (originalGraph.containsEdge(i+"", victim+""))
						originalFingerprint += "1";
					else 
						originalFingerprint += "0";
				}
				
				int cardinalityOfTheSubset = 0;
				boolean victimInsideSubset = false;
				for (String vertex : graph.vertexSet()) {
					String tmpFingerprint = "";
					boolean vertInCandidate = false;
					for (int i = 0; !vertInCandidate && i < candidate.length; i++) {
						if (vertex.equals(candidate[i]))
							vertInCandidate = true;
						else if (graph.containsEdge(candidate[i], vertex))
							tmpFingerprint += "1";
						else
							tmpFingerprint += "0";
					}
					if (!vertInCandidate && tmpFingerprint.equals(originalFingerprint)) {
						cardinalityOfTheSubset++;
						if (victim == Integer.parseInt(vertex))
							victimInsideSubset = true;
					}
				}
				
				/*Trujillo- Feb 9, 2016
				 * Note that, the probability to identify this victim is either 0 or 
				 * 1/cardinalityOfTheSubset
				 * The total probability of identifying all victims is the product
				 * While the probability becomes 0 if at least one victim cannot be identified*/
				if (cardinalityOfTheSubset != 0 && victimInsideSubset && successProbForCandidate != 0)
					successProbForCandidate *= 1d / cardinalityOfTheSubset;
				else
					successProbForCandidate = 0;
			}
			
			/*Trujillo- Feb 9, 2016
			 * For each candidate we sum its probability of success. The total probability is the average*/
			sumPartialSuccessProbs += successProbForCandidate;
		}
		return sumPartialSuccessProbs / candidates.size();
	}
	
	// Code taken from Rolando's old Statistics class
	protected List<String[]> getPotentialAttackerCandidates(int[] fingerprintDegrees, boolean[][] fingerprintLinks, UndirectedGraph<String, DefaultEdge> graph) {
		GenericTreeNode<String> root = new GenericTreeNode<>("root");
		List<GenericTreeNode<String>> currentLevel = new LinkedList<>();
		List<GenericTreeNode<String>> nextLevel = new LinkedList<>();
		for (int i = 0; i < fingerprintDegrees.length; i++) {
			nextLevel = new LinkedList<>();
			for (String vertex : graph.vertexSet()) {
				int degree = graph.degreeOf(vertex);
				if (degree == fingerprintDegrees[i]) {
					if (i == 0) {
						/*Trujillo- Feb 4, 2016
						 * At the beggining we just need to add the node as a child of the root*/
						GenericTreeNode<String> newChild = new GenericTreeNode<>(vertex);
						root.addChild(newChild);
						nextLevel.add(newChild);
					}
					else {
						/*Trujillo- Feb 4, 2016
						 * Now we iterate over the last level and add the new vertex if possible*/
						for (GenericTreeNode<String> lastVertex : currentLevel){
							boolean ok = true;
							GenericTreeNode<String> tmp = lastVertex;
							int pos = i - 1;
							while (!tmp.equals(root)){
								//we first check whether the vertex has been already considered
								if (tmp.getData().equals(vertex)){
									//this happens because this vertex has been considered already here
									ok = false;
									break;
								}
								//we also check that the link is consistent with fingerprintLinks
								if (graph.containsEdge(vertex, tmp.getData()) && !fingerprintLinks[i][pos]) {
									ok = false;
									break;
								}
								if (!graph.containsEdge(vertex, tmp.getData()) && fingerprintLinks[i][pos]) {
									ok = false;
									break;
								}
								pos--;
								tmp = tmp.getParent();
							}
							if (ok) {
								//we should add this vertex as a child
								tmp = new GenericTreeNode<>(vertex);
								lastVertex.addChild(tmp);
								nextLevel.add(tmp);
							}
						}
					}
				}
			}
			/*Trujillo- Feb 4, 2016
			 * Now we iterate over the current level to check whether a branch could not continue
			 * in which case we remove it completely*/
			currentLevel = nextLevel;
		}
		/*Trujillo- Feb 4, 2016
		 * Now we build subgraphs out of this candidate*/
		return buildListOfCandidates(root, graph, fingerprintDegrees.length, fingerprintDegrees.length);
		
	}
	
	// Code taken from Rolando's old Statistics class
	protected List<String[]> buildListOfCandidates(GenericTreeNode<String> root, UndirectedGraph<String, DefaultEdge> graph, int pos, int size) {
		List<String[]> result = new LinkedList<>();
		if (pos < 0) 
			throw new RuntimeException();
		if (root.isALeaf()) {
			if (pos > 0) return result;
			String[] candidates = new String[size];
			candidates[size - pos - 1] = root.getData();
			result.add(candidates);
			return result;
		}
		for (GenericTreeNode<String> child : root.getChildren()){
			List<String[]> subcandidates = buildListOfCandidates(child, graph, pos-1, size);
			if (!root.isRoot()) {
				for (String[] subcandidate : subcandidates) {
					//we add the node and its connections
					subcandidate[size-pos-1] = root.getData();
				}
			}
			result.addAll(subcandidates);
		}
		return result;
	}
	
	public static void main(String[] args) {

		
	}

}
