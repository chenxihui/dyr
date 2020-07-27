package enterprise.sequence.attacks;

import java.math.RoundingMode;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

import org.jgrapht.Graph;
import org.jgrapht.UndirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;
import com.google.common.math.LongMath;
import attacks.SnapshotInformation;
import enterprise.sequence.generators.BarabasiAlbertSequenceGenerator;
import enterprise.sequence.generators.Controller;
import net.vivin.GenericTreeNode;
import util.FSimCoincidenceCount;
import util.FingerprintSimilarity;

public class SequenceOriginalWalkBasedAttackSimulator extends enterprise.sequence.attacks.SybilAttackSimulatorMe {
	protected class FingerprintSetMatchingReturnValue {
		public Set<Map<Integer, String>> matches;
		public int maxSimilarity;

		public FingerprintSetMatchingReturnValue(Set<Map<Integer, String>> matches, int maxSimilarity) {
			this.matches = matches;
			this.maxSimilarity = maxSimilarity;
		}
	}

	protected boolean limitRunningTime = false;
	protected volatile boolean subgraphSearchOvertimed = false;

	protected class StopSubgraphSearchTask extends TimerTask {
		public void run() {
			if (limitRunningTime)
				subgraphSearchOvertimed = true;
		}
	}

	SecureRandom random = new SecureRandom();

	protected ArrayList<Integer> sybilList = new ArrayList<Integer>();
	protected Hashtable<String, String> fingerprints = new Hashtable<>();
	protected ArrayList<String> fingerprintKeys = new ArrayList<String>();
	protected ArrayList<String> victimList = new ArrayList<String>();
	protected int maxEditDistance;

	Hashtable<String, Double> weakestFingerprint_attack0 = new Hashtable<String, Double>();
	Hashtable<String, Double> weakestFingerprint_attack1 = new Hashtable<String, Double>();
	Hashtable<String, Double> weakestFingerprint_attack2 = new Hashtable<String, Double>();

	public static SnapshotInformation snapshotInformation;
	protected boolean applyApproxFingerprintMatching;

	protected List<String> finalVictimList = new ArrayList<String>();

	List<String[]> originalCurrentCandidates0_intersect = new ArrayList<String[]>();
	List<String[]> originalCurrentCandidates0_noIntersect = new ArrayList<String[]>();

	List<String[]> originalCurrentCandidates1_intersect = new ArrayList<String[]>();
	List<String[]> originalCurrentCandidates1_noIntersect = new ArrayList<String[]>();

	List<String[]> originalCurrentCandidates2_intersect = new ArrayList<String[]>();
	List<String[]> originalCurrentCandidates2_noIntersect = new ArrayList<String[]>();

	protected int attackerCount, victimCount;

	// Case 1: We only use this and nothing else
	Controller controller = new Controller();
	ArrayList<Graph<String, DefaultEdge>> snapshotList = controller.getSnapshotList();

	ArrayList<Double> probabilities = new ArrayList<Double>();
	ArrayList<Double> allProbabilities = new ArrayList<Double>();

	public SequenceOriginalWalkBasedAttackSimulator() {
		maxEditDistance = 16; //{4,8,16}
		long vertexSize = BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size();
		attackerCount = LongMath.log2(vertexSize, RoundingMode.UP);
	}

	public void createInitialAttackerSubgraph(int victimCount) {
		System.out.println("You just created an initial attack on the graph.");
		System.out.println("When evolving the graph you can only send three values as parameters");
		System.out.println("1 - Add sybils");
		System.out.println("2 - Add victims");
		System.out.println("3 - Flip connections");
		/*
		 * The BarabasiAlbertSequenceGenerator.getGraph() is assumed to satisfy all
		 * requirements, notably vertices being labeled from attackerCount on, and
		 * connectivity if required
		 */

		this.victimCount = victimCount;

		if (victimCount == 0)
			victimCount = 1;

		if (attackerCount + victimCount > BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size())
			victimCount = BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size() - attackerCount;

		int sibil = -1;
		for (int j = 0; j < attackerCount; j++) {
			BarabasiAlbertSequenceGenerator.getGraph().addVertex(sibil + "");// it's adding attackers
			sybilList.add(Integer.valueOf(sibil));
			sibil--;
		}

		int initialIinterations = (attackerCount + victimCount) - attackerCount;

		for (int j = 0; j < initialIinterations; j++) {
			String fingerprint = null;
			do {
				fingerprint = Integer.toBinaryString(random.nextInt((int) Math.pow(2, attackerCount) - 1) + 1);
				while (fingerprint.length() < attackerCount)
					fingerprint = "0" + fingerprint;

			} while (fingerprints.containsKey(fingerprint));
			fingerprintKeys.add(fingerprint);
			fingerprints.put(fingerprint, fingerprint);

			for (int k = 0; k < fingerprint.length(); k++) {
				if (fingerprint.charAt(k) == '1') {
					// Check and break the loop when the number of victims if bigger then sybils
					BarabasiAlbertSequenceGenerator.getGraph().addEdge(j + "",
							Integer.toString(sybilList.get(k).intValue()) + "");
					String victim = j + "";
					if (!victimList.contains(victim)) {
						victimList.add(victim);
					}
				}
			}
		}

		if (attackerCount > 1) {
			for (int k = 0; k < attackerCount - 1; k++) {
				BarabasiAlbertSequenceGenerator.getGraph().addEdge(Integer.toString(sybilList.get(k).intValue()) + "",
						Integer.toString(sybilList.get(k + 1).intValue()) + "");
			}
		}

		// Connect all sybils with each other with 50% chance
		for (int i = 0; i < sybilList.size(); i++) {
			for (int j = 0; j < sybilList.size() - 1; j++) {
				if ((sybilList.get(i) + "").equals(sybilList.get(j) + "")) {
				} else {
					if (!BarabasiAlbertSequenceGenerator.getGraph().containsEdge(sybilList.get(i) + "",
							sybilList.get(j) + "")) {
						if (random.nextBoolean()) {
							BarabasiAlbertSequenceGenerator.getGraph().addEdge(sybilList.get(i) + "",
									sybilList.get(j) + "");
						}
					}
				}
			}
		}
	}

	@Override
	public void evolveAttackerSubgraph(int attackerCountQ, int victimCountQ, int choice) {

		switch (choice) {
		case 1:
			System.out.println("You chose to add only sybils.");
			addSybils();
			break;
		case 2:
			System.out.println("You chose to add only victims.");
			addVictims();
			break;
		case 3:
			System.out.println("You chose to only flip connections.");
			flipConnections();
			break;
		case 4:
			System.out.println("You chose to add only sybils with log formula.");
			addLogSybils();
			break;
		}

	}

	public static String changeKey(String key, Random rand) {
		// System.out.println("--------------------------");
		// System.out.println("Old Key: " + key);
		int randomCharPos = rand.nextInt(key.length());
		// System.out.println("Random Char position: " + randomCharPos);
		StringBuilder newKey = new StringBuilder(key);
		newKey.setCharAt(randomCharPos, key.charAt(randomCharPos) == '0' ? '1' : '0');
		// System.out.println("New Key: " + newKey);
		return newKey.toString();
	}

	public void addLogSybils() {
		long vertexSize = BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size();
		int totalSybils = LongMath.log2(vertexSize, RoundingMode.UP);
		int newSybilsAdded = totalSybils - attackerCount;

		if (attackerCount < totalSybils) {

			attackerCount = attackerCount + newSybilsAdded;
			// Add new sybils
			int sibil = sybilList.get(sybilList.size() - 1);
			sibil--;
			for (int j = 0; j < newSybilsAdded; j++) {
				BarabasiAlbertSequenceGenerator.getGraph().addVertex(sibil + "");// it's adding attackers
				sybilList.add(Integer.valueOf(sibil));
				sibil--;
			}

			// These go with attacker
			Hashtable<String, String> updatedFingerPrints = new Hashtable<>();
			ArrayList<String> updatedFingerPrintKeys = new ArrayList<String>();
			// Adding the extra 0s or 1s at the end of the fingerprints with the length of
			// new sybils
			for (int index = 0; index < fingerprints.size(); index++) {
				String key = fingerprintKeys.get(index);
				String fingerprint = fingerprints.get(key);
				fingerprint = fingerprint + generateRandomBinaryString(newSybilsAdded);
				updatedFingerPrintKeys.add(fingerprint);
				updatedFingerPrints.put(fingerprint, fingerprint);
			}
			fingerprintKeys.clear();
			fingerprintKeys = updatedFingerPrintKeys;
			fingerprints.clear();
			fingerprints = updatedFingerPrints;

			// Adding new edges after updating the fingerprints in the previous 'for' loop
			for (int index = 0; index < victimCount; index++) {
				String key = fingerprintKeys.get(index);
				String fingerprint = fingerprints.get(key);

				for (int k = 0; k < fingerprint.length(); k++) {
					if (fingerprint.charAt(k) == '1') {
						if (!BarabasiAlbertSequenceGenerator.getGraph().containsEdge(index + "",
								sybilList.get(k).intValue() + "")) {
							BarabasiAlbertSequenceGenerator.getGraph().addEdge(index + "",
									sybilList.get(k).intValue() + "");
							String victim = index + "";
							if (!victimList.contains(victim)) {
								victimList.add(victim);
							}
						}
					}
				}
			}

			// Create a chain of new sybils with the last sybil from the previous one
			for (int k = 0; k < attackerCount - 1; k++) {
				if (!BarabasiAlbertSequenceGenerator.getGraph().containsEdge(
						Integer.toString(sybilList.get(k).intValue()) + "",
						Integer.toString(sybilList.get(k + 1).intValue()) + "")) {
					BarabasiAlbertSequenceGenerator.getGraph().addEdge(
							Integer.toString(sybilList.get(k).intValue()) + "",
							Integer.toString(sybilList.get(k + 1).intValue()) + "");
				}
			}

			// Connect all sybils with each other with 50% chance
			for (int i = 0; i < sybilList.size(); i++) {
				for (int j = 0; j < sybilList.size() - 1; j++) {
					if ((sybilList.get(i) + "").equals(sybilList.get(j) + "")) {
					} else {
						if (!BarabasiAlbertSequenceGenerator.getGraph().containsEdge(sybilList.get(i) + "",
								sybilList.get(j) + "")) {
							if (random.nextBoolean()) {
								BarabasiAlbertSequenceGenerator.getGraph().addEdge(sybilList.get(i) + "",
										sybilList.get(j) + "");
							}
						}
					}
				}
			}

		}
	}

	public void addSybils() {
		Random rand = new Random();
		int newSybils = rand.nextInt(1) + 1;

		attackerCount = attackerCount + newSybils;
		// Add new sybils
		int sibil = sybilList.get(sybilList.size() - 1);
		sibil--;
		for (int j = 0; j < newSybils; j++) {
			BarabasiAlbertSequenceGenerator.getGraph().addVertex(sibil + "");// it's adding attackers
			sybilList.add(Integer.valueOf(sibil));
			sibil--;
		}

		Hashtable<String, String> updatedFingerPrints = new Hashtable<>();
		ArrayList<String> updatedFingerPrintKeys = new ArrayList<String>();
		// Adding the extra 0s or 1s at the end of the fingerprints with the length of
		// new sybils
		for (int index = 0; index < fingerprints.size(); index++) {
			String key = fingerprintKeys.get(index);
			String fingerprint = fingerprints.get(key);
			fingerprint = fingerprint + generateRandomBinaryString(newSybils);
			updatedFingerPrintKeys.add(fingerprint);
			updatedFingerPrints.put(fingerprint, fingerprint);
		}
		fingerprintKeys.clear();
		fingerprintKeys = updatedFingerPrintKeys;
		fingerprints.clear();
		fingerprints = updatedFingerPrints;
		// Adding new edges after updating the fingerprints in the previous 'for' loop
		for (int index = 0; index < victimCount; index++) {
			String key = fingerprintKeys.get(index);
			String fingerprint = fingerprints.get(key);

			for (int k = 0; k < fingerprint.length(); k++) {
				if (fingerprint.charAt(k) == '1') {
					if (!BarabasiAlbertSequenceGenerator.getGraph().containsEdge(index + "",
							sybilList.get(k).intValue() + "")) {
						BarabasiAlbertSequenceGenerator.getGraph().addEdge(index + "",
								sybilList.get(k).intValue() + "");
						String victim = index + "";
						if (!victimList.contains(victim)) {
							victimList.add(victim);
						}
					}
				}
			}
		}

		// Create a chain of new sybils with the last sybil from the previous one
		for (int k = 0; k < attackerCount - 1; k++) {
			if (!BarabasiAlbertSequenceGenerator.getGraph().containsEdge(
					Integer.toString(sybilList.get(k).intValue()) + "",
					Integer.toString(sybilList.get(k + 1).intValue()) + "")) {
				BarabasiAlbertSequenceGenerator.getGraph().addEdge(Integer.toString(sybilList.get(k).intValue()) + "",
						Integer.toString(sybilList.get(k + 1).intValue()) + "");
			}
		}

		// Connect all sybils with each other with 50% chance
		for (int i = 0; i < sybilList.size(); i++) {
			for (int j = 0; j < sybilList.size() - 1; j++) {
				if ((sybilList.get(i) + "").equals(sybilList.get(j) + "")) {
				} else {
					if (!BarabasiAlbertSequenceGenerator.getGraph().containsEdge(sybilList.get(i) + "",
							sybilList.get(j) + "")) {
						if (random.nextBoolean()) {
							BarabasiAlbertSequenceGenerator.getGraph().addEdge(sybilList.get(i) + "",
									sybilList.get(j) + "");
						}
					}
				}
			}
		}
	}

	public void addVictims() {
		Random rand = new Random();
		int newVictims = rand.nextInt(5) + 1;

		for (int j = victimCount; j < victimCount + newVictims; j++) {
			String fingerprint = null;
			do {
				fingerprint = Integer.toBinaryString(random.nextInt((int) Math.pow(2, this.attackerCount) - 1) + 1);
				while (fingerprint.length() < this.attackerCount)
					fingerprint = "0" + fingerprint;
			} while (fingerprints.containsKey(fingerprint));
			fingerprintKeys.add(fingerprint);
			fingerprints.put(fingerprint, fingerprint);

			for (int k = 0; k < fingerprint.length(); k++) {
				if (fingerprint.charAt(k) == '1') {
					BarabasiAlbertSequenceGenerator.getGraph().addEdge(j + "",
							Integer.toString(sybilList.get(k).intValue()) + "");
					String victim = j + "";
					if (!victimList.contains(victim)) {
						victimList.add(victim);
					}
				}
			}
		}
		victimCount = victimCount + newVictims;
	}

	public void flipConnections() {
		Random rand = new Random();
		int flipConnections = rand.nextInt(3) + 1;
		for (int index = 0; index < flipConnections; index++) {
			String[] keys = fingerprints.keySet().toArray(new String[fingerprints.size()]);
			int randomPos = rand.nextInt(keys.length);
			String oldKey = keys[randomPos];
			
			int importantPos = 0;
			justForFun: 
			for (int i = 0; i < fingerprintKeys.size(); i++) {
				if (fingerprintKeys.get(i).equals(oldKey)) {
					importantPos = i;
					break justForFun;
				}
			}
			
			String newKey = changeKey(oldKey, rand);
			while (fingerprints.containsKey(newKey)) {
				randomPos = rand.nextInt(keys.length);
				oldKey = keys[randomPos];
				justForFun: 
				for (int i = 0; i < fingerprintKeys.size(); i++) {
					if (fingerprintKeys.get(i).equals(oldKey)) {
						importantPos = i;
						break justForFun;
					}
				}
				newKey = changeKey(oldKey, rand);
			}
			fingerprints.put(newKey, newKey);
			fingerprints.remove(oldKey);
			fingerprintKeys.set(importantPos, newKey);

			for (int k = 0; k < newKey.length(); k++) {
				if (newKey.charAt(k) == '1') {
					if (BarabasiAlbertSequenceGenerator.getGraph().containsEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "")) {
						// do nothing
					} else {
						BarabasiAlbertSequenceGenerator.getGraph().addEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "");
						String victim = importantPos+ "";
						if (!victimList.contains(victim)) {
							victimList.add(victim);
						}
					}
				} else if (newKey.charAt(k) == '0') {
					if (BarabasiAlbertSequenceGenerator.getGraph().containsEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "")) {
						BarabasiAlbertSequenceGenerator.getGraph().removeEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "");
					}
				}
			}
		}
	}

	public double currentSuccessProbability_attack0(Graph<String, DefaultEdge> originalGraph, SimpleGraph<String, DefaultEdge> noisyGraph,
			boolean isIntersectUsed, boolean isFlippedFingerprintActive) {
		
		weakestFingerprint_attack0.clear();
		int[] sybilVertexDegrees = new int[this.attackerCount];
		boolean[][] sybilVertexLinks = new boolean[this.attackerCount][this.attackerCount];

		for (int i = 0; i < this.attackerCount; i++) {
			int index = sybilList.get(i);
			int deg = originalGraph.degreeOf(index + "");
			sybilVertexDegrees[i] = deg;
		}

//		for (int i = 0; i < this.attackerCount; i++) {   // Attackers are assumed to be the first attackerCount vertices in the BarabasiAlbertSequenceGenerator.getGraph(), because of the manner in which the attack was simulated 
//			sybilVertexDegrees[i] = originalGraph.degreeOf(i+"");
//		}

		for (int i = 0; i < this.attackerCount; i++) {
			for (int j = 0; j < this.attackerCount; j++) {
				if (originalGraph.containsEdge(sybilList.get(i) + "", sybilList.get(j) + ""))
					sybilVertexLinks[i][j] = true;
				else
					sybilVertexLinks[i][j] = false;
			}
		}

		List<String[]> candidates_initial;
		List<String[]> candidates;

		if (isIntersectUsed){
			if(originalCurrentCandidates0_intersect.isEmpty()){
				candidates = getPotentialAttackerCandidates(sybilVertexDegrees, sybilVertexLinks,noisyGraph);
				originalCurrentCandidates0_intersect = candidates;
			}else{
				candidates_initial = getPotentialAttackerCandidates(sybilVertexDegrees, sybilVertexLinks, noisyGraph);
				if(candidates_initial.isEmpty()){
					return 0;
				}
				candidates = getIntersectedCandidatesList(originalCurrentCandidates0_intersect, candidates_initial);

				if(candidates.isEmpty()){
					// do nothing
				}else{
					originalCurrentCandidates0_intersect = candidates;
				}
			}
			if (originalCurrentCandidates0_intersect.isEmpty())
				return 0;
		}else {
			candidates = getPotentialAttackerCandidates(sybilVertexDegrees, sybilVertexLinks, noisyGraph);
			originalCurrentCandidates0_noIntersect = candidates;
			if (originalCurrentCandidates0_noIntersect.isEmpty())
				return 0;
		}

		/*
		 * Trujillo- Feb 4, 2016 Now, for every victim, we obtain the original
		 * fingerprint and look for the subset S of vertices with the same fingerprint.
		 * - If the subset is empty, then the success probability is 0 - If the subset
		 * is not empty, but the original victim is not in S, then again the probability
		 * of success is 0 - Otherwise the probability of success is 1/|S|
		 */

		double sumPartialSuccessProbs = 0;
		for (String[] candidate : candidates) {
			double successProbForCandidate = 1d;
			for (int victim = 0; victim < victimList.size(); victim++) {

				/*
				 * Trujillo- Feb 9, 2016 We first obtain the original fingerprint
				 */

				String originalFingerprint = "";
				for (int i = 0; i < this.attackerCount; i++) {
					if (originalGraph.containsEdge(sybilList.get(i) + "", victimList.get(victim) + ""))
						originalFingerprint += "1";
					else
						originalFingerprint += "0";
				}
				// String originalFingerprint = fingerprintKeys.get(victim);

				int cardinalityOfTheSubset = 0;
				boolean victimInsideSubset = false;
				for (String vertex : noisyGraph.vertexSet()) {
					String tmpFingerprint = "";
					boolean vertInCandidate = false;
					for (int i = 0; !vertInCandidate && i < candidate.length; i++) {
						if (vertex.equals(candidate[i]))
							vertInCandidate = true;
						else if (noisyGraph.containsEdge(candidate[i], vertex))
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

				/*
				 * Trujillo- Feb 9, 2016 Note that, the probability to identify this victim is
				 * either 0 or 1/cardinalityOfTheSubset The total probability of identifying all
				 * victims is the product While the probability becomes 0 if at least one victim
				 * cannot be identified
				 */
				if (cardinalityOfTheSubset != 0 && victimInsideSubset && successProbForCandidate != 0) {
					successProbForCandidate *= 1d / cardinalityOfTheSubset;
					weakestFingerprint_attack0.put(originalFingerprint, successProbForCandidate);
				} else {
					successProbForCandidate = 0;
					weakestFingerprint_attack0.put(originalFingerprint, successProbForCandidate);
				}
			}

			/*
			 * Trujillo- Feb 9, 2016 For each candidate we sum its probability of success.
			 * The total probability is the average
			 */
			sumPartialSuccessProbs += successProbForCandidate;
		}
		if(weakestFingerprint_attack0.isEmpty()){
			return 0.0;
		}
		flipSpecificFingerPrint(getWeakestFingerprint(weakestFingerprint_attack0), isFlippedFingerprintActive);
		double result = sumPartialSuccessProbs / getCorrectList_0(isIntersectUsed).size();
		probabilities.add((Double) result);
		allProbabilities.add((Double) result);
		return result;
	}

	public double currentSuccessProbability_attack1(Graph<String, DefaultEdge> originalGraph, SimpleGraph<String, DefaultEdge> noisyGraph,boolean isIntersectUsed,
			boolean isFlippedFingerprintActive) {
		weakestFingerprint_attack1.clear();
		int[] sybilVertexDegrees = new int[this.attackerCount];
		boolean[][] sybilVertexLinks = new boolean[this.attackerCount][this.attackerCount];

		for (int i = 0; i < this.attackerCount; i++) {
			int index = sybilList.get(i);
			int deg = originalGraph.degreeOf(index + "");
			sybilVertexDegrees[i] = deg;
		}

//		for (int i = 0; i < this.attackerCount; i++) {   // Attackers are assumed to be the first attackerCount vertices in the BarabasiAlbertSequenceGenerator.getGraph(), because of the manner in which the attack was simulated 
//			sybilVertexDegrees[i] = originalGraph.degreeOf(i+"");
//		}

		for (int i = 0; i < this.attackerCount; i++) {
			for (int j = 0; j < this.attackerCount; j++) {
				if (originalGraph.containsEdge(sybilList.get(i) + "", sybilList.get(j) + ""))
					sybilVertexLinks[i][j] = true;
				else
					sybilVertexLinks[i][j] = false;
			}
		}

		List<String[]> candidates_initial;
		List<String[]> candidates;
		if (isIntersectUsed) {
			if(originalCurrentCandidates1_intersect.isEmpty()){
				candidates = getPotentialAttackerCandidatesBFS(sybilVertexDegrees, sybilVertexLinks,noisyGraph);
				originalCurrentCandidates1_intersect = candidates;
			}else{
				candidates_initial = getPotentialAttackerCandidatesBFS(sybilVertexDegrees, sybilVertexLinks, noisyGraph);
				if(candidates_initial.isEmpty()){
					return 0;
				}
				candidates = getIntersectedCandidatesList(originalCurrentCandidates1_intersect, candidates_initial);
				if(candidates.isEmpty()){

				}else{
					originalCurrentCandidates1_intersect = candidates;
				}
			}

			if (originalCurrentCandidates1_intersect.isEmpty())
				return 0;
		}else {
			candidates = getPotentialAttackerCandidatesBFS(sybilVertexDegrees, sybilVertexLinks,noisyGraph);
			originalCurrentCandidates1_noIntersect = candidates;
			if (originalCurrentCandidates1_noIntersect.isEmpty())
				return 0;
		}



		/*
		 * Trujillo- Feb 4, 2016 Now, for every victim, we obtain the original
		 * fingerprint and look for the subset S of vertices with the same fingerprint.
		 * - If the subset is empty, then the success probability is 0 - If the subset
		 * is not empty, but the original victim is not in S, then again the probability
		 * of success is 0 - Otherwise the probability of success is 1/|S|
		 */

		double sumPartialSuccessProbs = 0;
		for (String[] candidate : getCorrectList_1(isIntersectUsed)) {
			double successProbForCandidate = 1d;
			for (int victim = 0; victim < victimList.size(); victim++) {

				/*
				 * Trujillo- Feb 9, 2016 We first obtain the original fingerprint
				 */

				String originalFingerprint = "";
				for (int i = 0; i < this.attackerCount; i++) {
					if (originalGraph.containsEdge(sybilList.get(i) + "", victimList.get(victim) + ""))
						originalFingerprint += "1";
					else
						originalFingerprint += "0";
				}
				// String originalFingerprint = fingerprintKeys.get(victim);

				int cardinalityOfTheSubset = 0;
				boolean victimInsideSubset = false;
				for (String vertex : noisyGraph.vertexSet()) {
					String tmpFingerprint = "";
					boolean vertInCandidate = false;
					for (int i = 0; !vertInCandidate && i < candidate.length; i++) {
						if (vertex.equals(candidate[i]))
							vertInCandidate = true;
						else if (noisyGraph.containsEdge(candidate[i], vertex))
							tmpFingerprint += "1";
						else
							tmpFingerprint += "0";
					}
					if (!vertInCandidate && tmpFingerprint.equals(originalFingerprint)) {
						cardinalityOfTheSubset++;
						if (victim == Integer.parseInt(vertex))
							finalVictimList.add(victim + "");
						victimInsideSubset = true;
					}
				}

				/*
				 * Trujillo- Feb 9, 2016 Note that, the probability to identify this victim is
				 * either 0 or 1/cardinalityOfTheSubset The total probability of identifying all
				 * victims is the product While the probability becomes 0 if at least one victim
				 * cannot be identified
				 */
				if (cardinalityOfTheSubset != 0 && victimInsideSubset && successProbForCandidate != 0) {
					successProbForCandidate *= 1d / cardinalityOfTheSubset;
					weakestFingerprint_attack1.put(originalFingerprint, successProbForCandidate);
				} else {
					successProbForCandidate = 0;
					weakestFingerprint_attack1.put(originalFingerprint, successProbForCandidate);
				}
			}

			/*
			 * Trujillo- Feb 9, 2016 For each candidate we sum its probability of success.
			 * The total probability is the average
			 */
			sumPartialSuccessProbs += successProbForCandidate;
		}

		if(weakestFingerprint_attack1.isEmpty()){
			return 0.0;
		}

		flipSpecificFingerPrint(getWeakestFingerprint(weakestFingerprint_attack1), isFlippedFingerprintActive);
		
		double result1 = sumPartialSuccessProbs / getCorrectList_1(isIntersectUsed).size();
		probabilities.add((Double) result1);
		allProbabilities.add((Double) result1);
		snapshotInformation = new  SnapshotInformation(BarabasiAlbertSequenceGenerator.getGraph(),noisyGraph, finalVictimList,null, getCorrectList_1(isIntersectUsed));
		System.out.println(snapshotInformation.toString());
		return result1;
	}

	public double currentSuccessProbability_attack2(Graph<String, DefaultEdge> originalGraph, SimpleGraph<String, DefaultEdge> noisyGraph,
			boolean applyApproxFingerprintMatching, boolean isIntersectUsed, boolean isFlippedFingerprintActive) {

		/**
		 * In an initial implementation, the number of sybils for the
		 * non-error-correcting fingerprint was set and then the larger number of sybils
		 * for error-correcting fingerprints was determined. Now we do the opposite, an
		 * upper bound on the number of sybils is set, and the code determines the
		 * maximum number of non-redundant fingerprints that can be encoded into this
		 * bound
		 */
		// int finalAttackerCount = attackerCount;
		// int chunkCount = (attackerCount % codec.getMessageLength() == 0)?
		// attackerCount / codec.getMessageLength() : 1 + attackerCount /
		// codec.getMessageLength();
		// finalAttackerCount = chunkCount * codec.getCodewordLength();

		int[] sybilVertexDegrees = new int[this.attackerCount];
		boolean[][] sybilVertexLinks = new boolean[this.attackerCount][this.attackerCount];

		for (int i = 0; i < this.attackerCount; i++) {
			int index = sybilList.get(i);
			int deg = originalGraph.degreeOf(index + "");
			sybilVertexDegrees[i] = deg;
		}

		for (int i = 0; i < this.attackerCount; i++) {
			for (int j = 0; j < this.attackerCount; j++) {
				if (originalGraph.containsEdge(sybilList.get(i) + "", sybilList.get(j) + ""))
					sybilVertexLinks[i][j] = true;
				else
					sybilVertexLinks[i][j] = false;
			}
		}

		List<String[]> candidates_initial;
		List<String[]> candidates;

		if (isIntersectUsed) {

			if(originalCurrentCandidates2_intersect.isEmpty()){
				candidates = getPotentialAttackerCandidatesBFS(sybilVertexDegrees, sybilVertexLinks,noisyGraph);
				originalCurrentCandidates2_intersect = candidates;
			}else{
				candidates_initial = getPotentialAttackerCandidatesBFS(sybilVertexDegrees, sybilVertexLinks, noisyGraph);
				if(candidates_initial.isEmpty()){
					return 0;
				}
				candidates = getIntersectedCandidatesList(originalCurrentCandidates2_intersect, candidates_initial);
				if(candidates.isEmpty()){

				}else{
					originalCurrentCandidates2_intersect = candidates;
				}
			}
			if (originalCurrentCandidates2_intersect.isEmpty())
				return 0;

		} else {
			candidates = getPotentialAttackerCandidatesBFS(sybilVertexDegrees, sybilVertexLinks,noisyGraph);
			originalCurrentCandidates2_noIntersect = candidates;
			if (originalCurrentCandidates2_noIntersect.isEmpty())
				return 0;
		}



		double sumPartialSuccessProbs = 0;
		for (String[] candidate : getCorrectList_2(isIntersectUsed)) {

			double successProbForCandidate = 1d;

			ArrayList<String> originalFingerprints = new ArrayList<>();
			for (int victim = 0; victim < victimList.size(); victim++) {
				String fingerprint = "";
				for (int i = 0; i < this.attackerCount; i++) {
					if (originalGraph.containsEdge(sybilList.get(i) + "", victimList.get(victim) + ""))
						fingerprint += "1";
					else
						fingerprint += "0";
				}
				originalFingerprints.add(fingerprint);
			}

			if (applyApproxFingerprintMatching) {

				// We first find all the existing exact matchings, because no approximate search
				// needs to be done for them

				Set<String> candAsSet = new HashSet<>();
				for (String cv : candidate)
					candAsSet.add(cv);

				int sybilListSize = sybilList.size();
				int candidateListSize = candidate.length;

				// Compute all fingerprints
				HashMap<String, String> allFingerprints = new HashMap<>();
				for (String v : noisyGraph.vertexSet()) {
					String pvFingerprint = "";

					for (int i = 0; i < sybilList.size(); i++)
						if (noisyGraph.containsEdge(v, candidate[i]))
							pvFingerprint += "1";
						else
							pvFingerprint += "0";
					/**
					 * In an initial implementation, we were decoding the fingerprint for correcting
					 * possible errors. Now, we only use the encoding to increase edit-distance, but
					 * do not attempt to decode at this step
					 */
					// pvFingerprint = codec.correctedCodeWord(pvFingerprint);
					if (pvFingerprint.indexOf("1") != -1)
						allFingerprints.put(v, pvFingerprint);
				}

				Set<Integer> exactlyMatchedVictims = new HashSet<>();
				boolean exactMatchFailed = false;

				for (int victim = 0; victim < victimList.size(); victim++) {
					int bucketSizeVictim = 0;
					boolean victimInBucket = false;
					for (String v : noisyGraph.vertexSet())
						if (!candAsSet.contains(v) && allFingerprints.containsKey(v)&& allFingerprints.containsKey("" + victim)&& allFingerprints.get("" + victim).equals(allFingerprints.get(v))) {
							bucketSizeVictim++;
							if (v.equals("" + victim)) {
								victimInBucket = true;
								exactlyMatchedVictims.add(victim);
							}
							allFingerprints.remove(v); // This will no longer be a potential candidate for approximate
														// matchings
						}
					if (bucketSizeVictim > 0) {
						if (victimInBucket)
							successProbForCandidate *= 1d / (double) bucketSizeVictim;
						else {
							successProbForCandidate = 0d;
							exactMatchFailed = true;
							break;
						}
					}
				}

				if (!exactMatchFailed && exactlyMatchedVictims.size() < originalFingerprints.size())
					if (originalFingerprints.size() - exactlyMatchedVictims.size() <= allFingerprints.size()) {

						// FingerprintSetMatchingReturnValue matchingResult =
						// approxFingerprintMatching(anonymizedGraph, candidate, allFingerprints,
						// originalFingerprints, matchedVictims);
						FingerprintSetMatchingReturnValue matchingResult = approxFingerprintMatching(allFingerprints, originalFingerprints, exactlyMatchedVictims, attackerCount);

						if (matchingResult.maxSimilarity <= 0)
							successProbForCandidate = 0d;
						else
							successProbForCandidate *= 1d / (double) matchingResult.matches.size();

					} else // The remaining fingerprints are too few for the remaining unmatched victims
						successProbForCandidate = 0d;
			} else {

				// We will apply exact fingerprint matching, which will be based on Rolando's
				// implementation

				for (int victim = 0; victim < victimList.size(); victim++) {

					int cardinalityOfTheSubset = 0;
					boolean victimInsideSubset = false;
					for (String vertex : noisyGraph.vertexSet()) {
						String tmpFingerprint = "";
						boolean vertInCandidate = false;
						for (int i = 0; !vertInCandidate && i < candidate.length; i++) {
							if (vertex.equals(candidate[i]))
								vertInCandidate = true;
							else if (noisyGraph.containsEdge(candidate[i], vertex))
								tmpFingerprint += "1";
							else
								tmpFingerprint += "0";
						}
						if (!vertInCandidate) {
							/**
							 * In an initial implementation, we were decoding the fingerprint for correcting
							 * possible errors. Now, we only use the encoding to increase edit-distance, but
							 * do not attempt to decode at this step
							 */
							// if (useErrorCorrectingFingerprints)
							// tmpFingerprint = codec.correctedCodeWord(tmpFingerprint);
							if (tmpFingerprint.equals(originalFingerprints.get(victim))) {
								cardinalityOfTheSubset++;
								if (victim == Integer.parseInt(vertex))
									victimInsideSubset = true;
							}
						}
					}

					/*
					 * As implemented by Rolando, the probability to identify this victim is either
					 * 0 or 1/cardinalityOfTheSubset The total probability of identifying all
					 * victims is the product While the probability becomes 0 if at least one victim
					 * cannot be identified
					 */

					if (cardinalityOfTheSubset != 0 && victimInsideSubset && successProbForCandidate != 0)
						successProbForCandidate *= 1d / cardinalityOfTheSubset;
					else
						successProbForCandidate = 0;
				}
			}

			// For each candidate we sum its probability of success. The total probability
			// is the average
			sumPartialSuccessProbs += successProbForCandidate;
		}
		 double result2 = sumPartialSuccessProbs / getCorrectList_2(isIntersectUsed).size();
		  probabilities.add((Double) result2);
		  allProbabilities.add((Double) result2);
		  return result2;
		
		/*
		 * double result2 = sumPartialSuccessProbs / originalCurrentCandidates2.size();
		 * probabilities.add((Double) result2); allProbabilities.add((Double) result2);
		 * snapshotInformation = new
		 * SnapshotInformation(BarabasiAlbertSequenceGenerator.getGraph(),
		 * finalVictimList, originalCurrentCandidates1);
		 * System.out.println(snapshotInformation.toString()); return result2;
		 */
	}

	protected List<String[]> getPotentialAttackerCandidates(int[] fingerprintDegrees, boolean[][] fingerprintLinks, SimpleGraph<String, DefaultEdge> noisyGraph) {
		GenericTreeNode<String> root = new GenericTreeNode<>("root");
		List<GenericTreeNode<String>> currentLevel = new LinkedList<>();
		List<GenericTreeNode<String>> nextLevel = new LinkedList<>();
		for (int i = 0; i < fingerprintDegrees.length; i++) {
			nextLevel = new LinkedList<>();
			for (String vertex : noisyGraph.vertexSet()) {
				int degree = noisyGraph.degreeOf(vertex);
				if (degree == fingerprintDegrees[i]) {
					if (i == 0) {
						/*
						 * Trujillo- Feb 4, 2016 At the beggining we just need to add the node as a
						 * child of the root
						 */
						GenericTreeNode<String> newChild = new GenericTreeNode<>(vertex);
						root.addChild(newChild);
						nextLevel.add(newChild);
					} else {
						/*
						 * Trujillo- Feb 4, 2016 Now we iterate over the last level and add the new
						 * vertex if possible
						 */
						for (GenericTreeNode<String> lastVertex : currentLevel) {
							boolean ok = true;
							GenericTreeNode<String> tmp = lastVertex;
							int pos = i - 1;
							while (!tmp.equals(root)) {
								// we first check whether the vertex has been already considered
								if (tmp.getData().equals(vertex)) {
									// this happens because this vertex has been considered already here
									ok = false;
									break;
								}
								// we also check that the link is consistent with fingerprintLinks
								if (noisyGraph.containsEdge(vertex, tmp.getData())
										&& !fingerprintLinks[i][pos]) {
									ok = false;
									break;
								}
								if (!noisyGraph.containsEdge(vertex, tmp.getData())
										&& fingerprintLinks[i][pos]) {
									ok = false;
									break;
								}
								pos--;
								tmp = tmp.getParent();
							}
							if (ok) {
								// we should add this vertex as a child
								tmp = new GenericTreeNode<>(vertex);
								lastVertex.addChild(tmp);
								nextLevel.add(tmp);
							}
						}
					}
				}
			}
			/*
			 * Trujillo- Feb 4, 2016 Now we iterate over the current level to check whether
			 * a branch could not continue in which case we remove it completely
			 */
			currentLevel = nextLevel;
		}
		/*
		 * Trujillo- Feb 4, 2016 Now we build subgraphs out of this candidate
		 */
		return buildListOfCandidates(root, noisyGraph, fingerprintDegrees.length, fingerprintDegrees.length);

	}

	protected List<String[]> getPotentialAttackerCandidatesBFS(int[] fingerprintDegrees, boolean[][] fingerprintLinks,SimpleGraph<String, DefaultEdge> noisyGraph) {

		int minLocDistValue = 1 + (noisyGraph.vertexSet().size()
				* (noisyGraph.vertexSet().size() - 1)) / 2; // One more than the maximal possible distance (the total amount of edges). This is "positive infinity" in this context.
		Set<String> vertsMinDistValue = new HashSet<>();
		for (String v : noisyGraph.vertexSet()) {
			int dist = Math.abs(fingerprintDegrees[0] - noisyGraph.degreeOf(v)); 
			// If called,  the function edgeEditDistanceWeaklyInduced would return this value. We don't to avoid creating the singleton lists
			if (dist < minLocDistValue) {
				minLocDistValue = dist;
				vertsMinDistValue.clear();
				vertsMinDistValue.add(v);
			} else if (dist == minLocDistValue)
				vertsMinDistValue.add(v);
		}

		List<String[]> finalCandidates = new ArrayList<>();

		if (minLocDistValue <= maxEditDistance)
			if (fingerprintDegrees.length == 1)
				for (String v : vertsMinDistValue)
					finalCandidates.add(new String[] { v });
			else { // fingerprintDegrees.length > 1

				// Explore recursively
				int minGlbDistValue = 1 + (noisyGraph.vertexSet().size()
						* (noisyGraph.vertexSet().size() - 1)) / 2; // One more than the maximal possible distance (the total amount of edges). This is "positive infinity" in this context.
				List<List<String>> candidatesMinGlb = new ArrayList<>();
				for (String v : vertsMinDistValue) {
					List<String> currentPartialCandidate = new ArrayList<>();
					currentPartialCandidate.add(v);
					List<List<String>> returnedPartialCandidates = new ArrayList<>();
					int glbDist = getPotentialAttackerCandidatesBFS1(fingerprintDegrees, fingerprintLinks, noisyGraph,
							currentPartialCandidate, returnedPartialCandidates);
					if (glbDist < minGlbDistValue) {
						minGlbDistValue = glbDist;
						candidatesMinGlb.clear();
						candidatesMinGlb.addAll(returnedPartialCandidates);
					} else if (glbDist == minGlbDistValue)
						candidatesMinGlb.addAll(returnedPartialCandidates);
				}

				for (List<String> cand : candidatesMinGlb)
					finalCandidates.add(cand.toArray(new String[cand.size()]));
			}

		return finalCandidates;
	}

	protected int getPotentialAttackerCandidatesBFS1(int[] fingerprintDegrees, boolean[][] fingerprintLinks,SimpleGraph<String, DefaultEdge> noisyGraph,
			List<String> currentPartialCandidate, List<List<String>> partialCandidates2Return) {

		int minLocDistValue = 1 + (noisyGraph.vertexSet().size()
				* (noisyGraph.vertexSet().size() - 1)) / 2; // One more than the maximal
																							// possible distance (the
																							// total amount of edges).
																							// This is "positive
																							// infinity" in this
																							// context.
		Set<String> vertsMinDistValue = new HashSet<>();

		List<String> currentSybPrefix = new ArrayList<>();
		for (int i = 0; i < currentPartialCandidate.size() + 1; i++) {
			int index = sybilList.get(i);
			currentSybPrefix.add("" + index);
		}

		for (String v : noisyGraph.vertexSet())
			if (!currentPartialCandidate.contains(v)) {

				List<String> newCand = new ArrayList<>(currentPartialCandidate);
				newCand.add(v);

				int dist = edgeEditDistanceWeaklyInduced(noisyGraph, currentSybPrefix,
						newCand);

				if (dist < minLocDistValue) {
					minLocDistValue = dist;
					vertsMinDistValue.clear();
					vertsMinDistValue.add(v);
				} else if (dist == minLocDistValue)
					vertsMinDistValue.add(v);
			}

		if (minLocDistValue <= maxEditDistance)
			if (fingerprintDegrees.length <= currentPartialCandidate.size() + 1) {
				for (String v : vertsMinDistValue) {
					List<String> newCand = new ArrayList<>(currentPartialCandidate);
					newCand.add(v);
					partialCandidates2Return.add(newCand);
				}
				return minLocDistValue;
			}
			else {

				// Explore recursively
				int minGlbDistValue = 1 + (noisyGraph.vertexSet().size()
						* (noisyGraph.vertexSet().size() - 1)) / 2; // One more than the
																									// maximal possible
																					// distance (the
																									// total amount of
																									// edges). This is
																									// "positive
																									// infinity" in this
																									// context.
				List<List<String>> candidatesMinGlb = new ArrayList<>();
				for (String v : vertsMinDistValue) {
					List<String> newCurrentPartialCandidate = new ArrayList<>(currentPartialCandidate);
					newCurrentPartialCandidate.add(v);
					List<List<String>> returnedPartialCandidates = new ArrayList<>();
					int glbDist = getPotentialAttackerCandidatesBFS1(fingerprintDegrees, fingerprintLinks,noisyGraph,
							newCurrentPartialCandidate, returnedPartialCandidates);
					if (glbDist < minGlbDistValue) {
						minGlbDistValue = glbDist;
						candidatesMinGlb.clear();
						candidatesMinGlb.addAll(returnedPartialCandidates);
					} else if (glbDist == minGlbDistValue)
						candidatesMinGlb.addAll(returnedPartialCandidates);
				}

				partialCandidates2Return.addAll(candidatesMinGlb);
				return minGlbDistValue;
			}
		else // minLocDistValue > maxEditDistance
			return 1 + (noisyGraph.vertexSet().size()
					* (noisyGraph.vertexSet().size() - 1)) / 2; // One more than the
																								// maximal possible
																								// distance (the total
																								// amount of edges).
																								// This is "positive
																								// infinity" in this
																								// context.
	}

	protected List<String[]> buildListOfCandidates(GenericTreeNode<String> root, SimpleGraph<String, DefaultEdge> noisyGraph, int pos, int size) {
		List<String[]> result = new LinkedList<>();
		if (pos < 0)
			throw new RuntimeException();
		if (root.isALeaf()) {
			if (pos > 0)
				return result;
			String[] candidates = new String[size];
			candidates[size - pos - 1] = root.getData();
			result.add(candidates);
			return result;
		}
		for (GenericTreeNode<String> child : root.getChildren()) {
			List<String[]> subcandidates = buildListOfCandidates(child, noisyGraph, pos - 1, size);
			if (!root.isRoot()) {
				for (String[] subcandidate : subcandidates) {
					// we add the node and its connections
					subcandidate[size - pos - 1] = root.getData();
				}
			}
			result.addAll(subcandidates);
		}
		return result;
	}

	public void updateProbabilities() {
		double lastProbability = (probabilities.get(probabilities.size() - 1)).doubleValue();
		if (probabilities.size() > 1) {
			for (int i = 0; i < probabilities.size(); i++) {
				probabilities.set(i, (Double) lastProbability);
			}
		}

	}

	@Override
	public double updateSuccessProbabilities(int attackerCount, int victimCount,
			UndirectedGraph<String, DefaultEdge> graph, UndirectedGraph<String, DefaultEdge> originalGraph) {
		//currentSuccessProbability_attack0(originalGraph, false, false);

		return 0;
	}

	public String generateRandomBinaryString(int length) {
		String response = "";
		for (int i = 0; i < length; i++) {
			if (Math.random() > 0.5) {
				response += "1";
			} else {
				response += "0";
			}
		}
		return response;
	}

	@Override
	public double currentSuccessProbability(int attackerCount, int victimCount,
			UndirectedGraph<String, DefaultEdge> graph, UndirectedGraph<String, DefaultEdge> originalGraph) {
		// TODO Auto-generated method stub
		return 0;
	}


	protected int edgeEditDistanceWeaklyInduced(SimpleGraph<String, DefaultEdge> noisyGraph, List<String> vertSet1,	List<String> vertSet2) {
		if (vertSet1.size() == vertSet2.size()) {
			int diffCount = 0;
			List<Integer> externalDegrees1 = new ArrayList<>();
			List<Integer> externalDegrees2 = new ArrayList<>();
			for (int i = 0; i < vertSet1.size(); i++) {
				externalDegrees1.add(noisyGraph.degreeOf(vertSet1.get(i)));
				externalDegrees2.add(noisyGraph.degreeOf(vertSet2.get(i)));
			}
			for (int i = 0; i < vertSet1.size() - 1; i++)
				for (int j = i + 1; j < vertSet1.size(); j++)
					if (noisyGraph.containsEdge(vertSet1.get(i), vertSet1.get(j))) {
						externalDegrees1.set(i, externalDegrees1.get(i) - 1);
						if (noisyGraph.containsEdge(vertSet2.get(i), vertSet2.get(j)))
							externalDegrees2.set(i, externalDegrees2.get(i) - 1);
						else
							diffCount++;
					} else // !BarabasiAlbertSequenceGenerator.getGraph().containsEdge(vertSet1.get(i),
							// vertSet1.get(j))
					if (noisyGraph.containsEdge(vertSet2.get(i), vertSet2.get(j))) {
						diffCount++;
						externalDegrees2.set(i, externalDegrees2.get(i) - 1);
					}
			// else
			// !BarabasiAlbertSequenceGenerator.getGraph().containsEdge(vertSet2.get(i),
			// vertSet2.get(j))

			int dist = diffCount;
			for (int i = 0; i < vertSet1.size(); i++)
				dist += Math.abs(externalDegrees1.get(i) - externalDegrees2.get(i));

			return dist;
		}
		return 1 + (noisyGraph.vertexSet().size()
				* (noisyGraph.vertexSet().size() - 1)) / 2; // One more than the maximal
																							// possible distance (the
																							// total amount of edges).
																							// This is "positive
																							// infinity" in this
																							// context.
	}




	public ArrayList<Double> printProbabilities() {
		for (int i = 0; i < probabilities.size(); i++) {
			System.out.println((probabilities.get(i)).doubleValue());
		}
		return probabilities;
	}

	@Override
	public void createInitialAttackerSubgraph(int attackerCount, int victimCount) {
		// TODO Auto-generated method stub

	}

	public List<String[]> getIntersectedCandidatesList(List<String[]> original, List<String[]> current_new) {
		if(original.get(0).length != current_new.get(0).length){
			return current_new;
		}
		int sybilSize = sybilList.size();

		List<String[]> intersections = new ArrayList<String[]>();
		for (String[] strings : original) {
			for (String[] strings2 : current_new) {
				if (Arrays.equals(strings, strings2)) {
					intersections.add(strings);
				}
			}
		}
		List<String[]> noDuplicateIntersections = intersections.stream().distinct().collect(Collectors.toList());
		if (original.isEmpty())
			return current_new;
		else
			return noDuplicateIntersections;
	}

	protected FingerprintSetMatchingReturnValue approxFingerprintMatching(
			Map<String, String> fingerprintsPossibleVictims, List<String> originalFingerprints,
			Set<Integer> matchedOrigFingerprints, int attackerCount) {

		FingerprintSimilarity fsim = new FSimCoincidenceCount();

		// Find all choices for the next match. Each choice is a pair (yi,v) where yi is
		// a real victim.
		int maxSim = -1;
		Map<Integer, Set<String>> bestLocalMatches = new HashMap<>();

		for (int ordOrigFP = 0; ordOrigFP < originalFingerprints.size(); ordOrigFP++)
			if (!matchedOrigFingerprints.contains(ordOrigFP)) {
				for (String pv : fingerprintsPossibleVictims.keySet()) {
					int sim = fsim.similarity(originalFingerprints.get(ordOrigFP), fingerprintsPossibleVictims.get(pv));
					if (sim > maxSim) {
						maxSim = sim;
						bestLocalMatches.clear();
						Set<String> pvictims = new HashSet<>();
						pvictims.add(pv);
						bestLocalMatches.put(ordOrigFP, pvictims);
					} else if (sim == maxSim) {
						if (bestLocalMatches.containsKey(ordOrigFP))
							bestLocalMatches.get(ordOrigFP).add(pv);
						else {
							Set<String> pvictims = new HashSet<>();
							pvictims.add(pv);
							bestLocalMatches.put(ordOrigFP, pvictims);
						}
					}
				}
			}

		// Get matches

		Set<Map<Integer, String>> allMatches = new HashSet<>();

		if (maxSim == -1) // This happens if there were too few available fingerprints
			return new FingerprintSetMatchingReturnValue(allMatches, -1);

		if (matchedOrigFingerprints.size() + 1 < originalFingerprints.size()) { // Recursion can continue at least one
																				// more level from here

			int maxSimRestOfMatching = -1;

			for (Integer ordOrigFP : bestLocalMatches.keySet())
				for (String pv : bestLocalMatches.get(ordOrigFP)) {
					Set<Integer> newMatchedOrigFingerprints = new HashSet<>();
					newMatchedOrigFingerprints.add(ordOrigFP);
					HashMap<String, String> fingerprintsRemainingPossibleVictims = new HashMap<>(
							fingerprintsPossibleVictims);
					fingerprintsRemainingPossibleVictims.remove(pv);

					FingerprintSetMatchingReturnValue resultRemainingMatching = approxFingerprintMatching(
							fingerprintsRemainingPossibleVictims, originalFingerprints, newMatchedOrigFingerprints,
							attackerCount);

					if (resultRemainingMatching.maxSimilarity != -1) {
						if (resultRemainingMatching.maxSimilarity > maxSimRestOfMatching) {
							maxSimRestOfMatching = resultRemainingMatching.maxSimilarity;
							allMatches.clear();
							for (Map<Integer, String> mms : resultRemainingMatching.matches) {
								mms.put(ordOrigFP, pv);
								allMatches.add(mms);
							}
						} else if (resultRemainingMatching.maxSimilarity == maxSimRestOfMatching)
							for (Map<Integer, String> mms : resultRemainingMatching.matches) {
								mms.put(ordOrigFP, pv);
								allMatches.add(mms);
							}
					}

				}

			if (maxSimRestOfMatching <= 0)
				return new FingerprintSetMatchingReturnValue(allMatches, -1);
			else
				return new FingerprintSetMatchingReturnValue(allMatches, maxSimRestOfMatching);

		} else { // Recursion stops when matchedOrigFingerprints.size() ==
					// originalFingerprints.size() - 1, that is, we are doing the last matching
			boolean realVictimMatched = false;
			for (Integer ordOrigFP : bestLocalMatches.keySet()) {
				for (String v : bestLocalMatches.get(ordOrigFP)) {
					Map<Integer, String> entry = new HashMap<>();
					entry.put(ordOrigFP, v);
					allMatches.add(entry);
					if (v.equals("" + this.attackerCount + ordOrigFP))
						realVictimMatched = true;
				}
			}
			if (realVictimMatched)
				return new FingerprintSetMatchingReturnValue(allMatches, maxSim);
			else
				return new FingerprintSetMatchingReturnValue(allMatches, -1);
		}
	}

	/*
	 * public void print(Graph<String, DefaultEdge>
	 * BarabasiAlbertSequenceGenerator.getGraph()) { Set<String> vertexSet =
	 * BarabasiAlbertSequenceGenerator.getGraph().vertexSet(); ArrayList vertexList
	 * = new ArrayList<String>(); vertexList.addAll(vertexSet); for(int
	 * index=0;index < vertexList.size();index++) { Set<DefaultEdge> DefaultEdges=
	 * BarabasiAlbertSequenceGenerator.getGraph().edgesOf((String)
	 * vertexList.get(index)); for(DefaultEdge defaultEdge: DefaultEdges) {
	 * System.out.println(defaultEdge.toString()); } }
	 */

	public String getWeakestFingerprint(Hashtable<String, Double> hashtable) {
		Double min = Double.MAX_VALUE;
		String fingerprint = "";
		for (String key : hashtable.keySet()) {
			Double tmp = hashtable.get(key);
			if (tmp.compareTo(min) < 0) {
				min = tmp;
				fingerprint = key;
			}
		}
		return fingerprint;
	}

	public void flipSpecificFingerPrint(String currentFingerPrint, boolean flipOrNot) {
		if (flipOrNot) {
			Random rand = new Random();
			
			int importantPos = 0;
			justForFun: 
			for (int i = 0; i < fingerprintKeys.size(); i++) {
				if (fingerprintKeys.get(i).equals(currentFingerPrint)) {
					importantPos = i;
					break justForFun;
				}
			}
			
			String newKey = changeKey(currentFingerPrint, rand);
			
			
			while (fingerprints.containsKey(newKey)) {
				newKey = changeKey(currentFingerPrint, rand);
			}
			
			fingerprints.put(newKey, newKey);
			fingerprints.remove(currentFingerPrint);
			fingerprintKeys.set(importantPos, newKey);
			
			for (int k = 0; k < newKey.length(); k++) {
				if (newKey.charAt(k) == '1') {
					if (BarabasiAlbertSequenceGenerator.getGraph().containsEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "")) {
						// do nothing
					} else {
						BarabasiAlbertSequenceGenerator.getGraph().addEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "");
						String victim = importantPos+ "";
						if (!victimList.contains(victim)) {
							victimList.add(victim);
						}
					}
				} else if (newKey.charAt(k) == '0') {
					if (BarabasiAlbertSequenceGenerator.getGraph().containsEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "")) {
						BarabasiAlbertSequenceGenerator.getGraph().removeEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "");
					}
				}
			}
		} 
	}
	public void flipSpecificFingerPrint(int victimIndex, boolean flipOrNot) {
		if (flipOrNot) {
			Random rand = new Random();
			
			int importantPos = victimIndex;
			
			String currentFingerPrint = fingerprintKeys.get(importantPos);
			String newKey = changeKey(currentFingerPrint, rand);
			
			
			while (fingerprints.containsKey(newKey)) {
				newKey = changeKey(currentFingerPrint, rand);
			}
			
			fingerprints.put(newKey, newKey);
			fingerprints.remove(currentFingerPrint);
			fingerprintKeys.set(importantPos, newKey);
			
			for (int k = 0; k < newKey.length(); k++) {
				if (newKey.charAt(k) == '1') {
					if (BarabasiAlbertSequenceGenerator.getGraph().containsEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "")) {
						// do nothing
					} else {
						BarabasiAlbertSequenceGenerator.getGraph().addEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "");
						String victim = importantPos+ "";
						if (!victimList.contains(victim)) {
							victimList.add(victim);
						}
					}
				} else if (newKey.charAt(k) == '0') {
					if (BarabasiAlbertSequenceGenerator.getGraph().containsEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "")) {
						BarabasiAlbertSequenceGenerator.getGraph().removeEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "");
					}
				}
			}
		} 
	}
	private List<String[]> getCorrectList_0(boolean isIntersectUsed){
		if(isIntersectUsed){
			return originalCurrentCandidates0_intersect;
		}else {
			return originalCurrentCandidates0_noIntersect;
		}
	}

	private List<String[]> getCorrectList_1(boolean isIntersectUsed){
		if(isIntersectUsed){
			return originalCurrentCandidates1_intersect;
		}else {
			return originalCurrentCandidates1_noIntersect;
		}
	}

	private List<String[]> getCorrectList_2(boolean isIntersectUsed){
		if(isIntersectUsed){
			return originalCurrentCandidates2_intersect;
		}else {
			return originalCurrentCandidates2_noIntersect;
		}
	}

}
