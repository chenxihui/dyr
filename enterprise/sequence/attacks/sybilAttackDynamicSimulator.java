package enterprise.sequence.attacks;

import java.math.RoundingMode;
import java.security.SecureRandom;
import java.util.*;

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

public class sybilAttackDynamicSimulator extends enterprise.sequence.attacks.SybilAttackSimulatorMe {
	protected class FingerprintSetMatchingReturnValue {
		public Set<Map<Integer, String>> matches;
		public int maxSimilarity;

		public FingerprintSetMatchingReturnValue(Set<Map<Integer, String>> matches, int maxSimilarity) {
			this.matches = matches;
			this.maxSimilarity = maxSimilarity;
		}
		public ArrayList<Map<Integer, String>> getMatches(){
			Iterator<Map<Integer, String>> iter = matches.iterator();
			ArrayList<Map<Integer, String>> rMatches = new ArrayList<Map<Integer, String>>();
			while(iter.hasNext()) {
				rMatches.add(iter.next());
			}
			return rMatches;
		}
	}
	protected class probResult{
		private double maxProb; 
		private double sumProb; 
		private double matchProb;
		public double getMatchProb() {
			return matchProb;
		}
		public void setMatchProb(double matchProb) {
			this.matchProb = matchProb;
		}
		public double getSumProb() {
			return sumProb;
		}
		public void setSumProb(double sumProb) {
			this.sumProb = sumProb;
		}
		public double getMaxProb() {
			return maxProb;
		}
		public void setMaxProb(double maxProb) {
			this.maxProb = maxProb;
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

	protected int last_number_of_sybils;
	protected ArrayList<Integer> sybilList = new ArrayList<Integer>();
	protected Hashtable<String, String> fingerprints = new Hashtable<>();
	protected ArrayList<String> fingerprintKeys = new ArrayList<String>();
	protected ArrayList<String> victimList = new ArrayList<String>();
	protected ArrayList<HashMap<String, Double>> probDistVictims; 
	protected int maxEditDistance;

	protected long BFS1StartTime = 0;
	Hashtable<String, Double> weakestFingerprint_attack0 = new Hashtable<String, Double>();
	Hashtable<String, Double> weakestFingerprint_attack1 = new Hashtable<String, Double>();
	Hashtable<String, Double> weakestFingerprint_attack2 = new Hashtable<String, Double>();

	public SnapshotInformation snapshotInformation;
	protected boolean applyApproxFingerprintMatching;

	protected List<String> finalVictimList = new ArrayList<String>();

	List<String[]> originalCurrentCandidates0_intersect = new ArrayList<String[]>();
	List<String[]> originalCurrentCandidates0_noIntersect = new ArrayList<String[]>();

	List<String[]> originalCurrentCandidates1_intersect = new ArrayList<String[]>();
	List<String[]> originalCurrentCandidates1_noIntersect = new ArrayList<String[]>();

	List<String[]> originalCurrentCandidates2_intersect = new ArrayList<String[]>();
	List<String[]> originalCurrentCandidates2_noIntersect = new ArrayList<String[]>();
	
	public HashMap<String, Integer> victimTargetedFrom;
	public HashMap<String, Integer> victimLastTargeted;
	protected int attackerCount, victimCount;

	// Case 1: We only use this and nothing else
	Controller controller = new Controller();
	ArrayList<Graph<String, DefaultEdge>> snapshotList = controller.getSnapshotList();

	ArrayList<probResult> probabilities = new ArrayList<probResult>();
	ArrayList<probResult> allProbabilities = new ArrayList<probResult>();
	private boolean timeout;
	private double timeLimit ;

	public sybilAttackDynamicSimulator() {
		maxEditDistance = 16; //{4,8,16}
		long vertexSize = BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size();
		attackerCount = LongMath.log2(vertexSize, RoundingMode.UP);
		probDistVictims = new ArrayList<HashMap<String, Double>>();
		this.victimTargetedFrom = new HashMap<String, Integer>();
		this.victimLastTargeted= new HashMap<String, Integer>();
		this.timeLimit = 600;
	}

	public void createInitialAttackerSubgraph(int victimCount) {
		/*
		System.out.println("You just created an initial attack on the graph.");
		System.out.println("When evolving the graph you can only send three values as parameters");
		System.out.println("1 - Add sybils");
		System.out.println("2 - Add victims");
		System.out.println("3 - Flip connections");
		*/

		System.out.println(" Start creating the initial sybil network ...");
		/*
		 * The BarabasiAlbertSequenceGenerator.getGraph() is assumed to satisfy all
		 * requirements, notably vertices being labeled from attackerCount on, and
		 * connectivity if required
		 */

		if (victimCount == 0)
			victimCount = 1;
		if(victimCount == -1) {
			this.victimCount = this.attackerCount;
			victimCount = this.victimCount;
		}else
			this.victimCount = victimCount;

		if (attackerCount + victimCount > BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size())
			victimCount = BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size() - attackerCount;

		int sibil = -1;
		for (int j = 0; j < attackerCount; j++) {
			BarabasiAlbertSequenceGenerator.getGraph().addVertex(sibil + "");// it's adding attackers
			BarabasiAlbertSequenceGenerator.birthSnapshot.put(sibil+"", BarabasiAlbertSequenceGenerator.num_snapshots-1);
			sybilList.add(Integer.valueOf(sibil));
			sibil--;
		}

		int initialIinterations = (attackerCount + this.victimCount) - attackerCount;

		ArrayList<String> vertexList = new ArrayList<String>(BarabasiAlbertSequenceGenerator.getGraph().vertexSet());

		for (int j = 0; j < initialIinterations; j++) {
			String fingerprint = null;
			do {
				fingerprint = Integer.toBinaryString(random.nextInt((int) Math.pow(2, attackerCount) - 1) + 1);
				while (fingerprint.length() < attackerCount)
					fingerprint = "0" + fingerprint;
			} while (fingerprints.containsKey(fingerprint));
			fingerprintKeys.add(fingerprint);
			fingerprints.put(fingerprint, fingerprint);

			//randomly select a vertex as the new victim
			int newvictimPos = new Random().nextInt(vertexList.size()-this.attackerCount);
			String newVictim = vertexList.get(newvictimPos);
			while (victimList.contains(newVictim)) {
				newvictimPos = new Random().nextInt(vertexList.size()-this.attackerCount);
				newVictim = vertexList.get(newvictimPos);
			}
			victimList.add(newVictim);
			this.victimTargetedFrom.put(newVictim, BarabasiAlbertSequenceGenerator.num_snapshots-1);

			for (int k = 0; k < fingerprint.length(); k++) {
				if (fingerprint.charAt(k) == '1') {
					//modified by Xihui
/*					BarabasiAlbertSequenceGenerator.getGraph().addEdge(j + "",
							Integer.toString(sybilList.get(k).intValue()) + "");
					String victim = j + "";
					if (!victimList.contains(victim)) {
						victimList.add(victim);
					}
					*/
					BarabasiAlbertSequenceGenerator.getGraph().addEdge(newVictim,
							Integer.toString(sybilList.get(k).intValue()) + "");
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
			System.out.println("Sybils randomly added.");
			addSybils();
			break;
		case 2:
			System.out.println("Victims randomly added.");
			addVictims(-1);
			break;
		case 3:
			System.out.println("Fingerprints randomly flipped.");
			flipConnections();
			break;
		case 4:
			System.out.println("Log N sybils preserved.");
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
		
		int num_to_change = new Random().nextInt(attackerCount);
		//num_to_change = attackerCount;
		for (int i = 1; i<=num_to_change; i++ ) {
		//	BarabasiAlbertSequenceGenerator.birthSnapshot.put("-"+i, BarabasiAlbertSequenceGenerator.num_snapshots);
			int pos = new Random().nextInt(attackerCount);
			while(!BarabasiAlbertSequenceGenerator.birthSnapshot.containsKey("-"+pos)||
					BarabasiAlbertSequenceGenerator.birthSnapshot.get("-"+pos)==
					BarabasiAlbertSequenceGenerator.num_snapshots-1)
			   pos = new Random().nextInt(attackerCount);
			BarabasiAlbertSequenceGenerator.birthSnapshot.put("-"+pos, BarabasiAlbertSequenceGenerator.num_snapshots-1);
			BarabasiAlbertSequenceGenerator.diedSnapshot.put("-"+pos, BarabasiAlbertSequenceGenerator.num_snapshots-1);
		}
		
		if (attackerCount < totalSybils) {

			attackerCount = attackerCount + newSybilsAdded;
			// Add new sybils
			int sibil = sybilList.get(sybilList.size() - 1);
			sibil--;
			for (int j = 0; j < newSybilsAdded; j++) {
				BarabasiAlbertSequenceGenerator.getGraph().addVertex(sibil + "");// it's adding attackers
				BarabasiAlbertSequenceGenerator.birthSnapshot.put(sibil+"", BarabasiAlbertSequenceGenerator.num_snapshots-1);
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
			for (int index = 0; index < this.victimCount; index++) {
				String key = fingerprintKeys.get(index);
				String fingerprint = fingerprints.get(key);

				for (int k = 0; k < fingerprint.length(); k++) {
					if (fingerprint.charAt(k) == '1') {
						if (!BarabasiAlbertSequenceGenerator.getGraph().containsEdge(victimList.get(index),
								sybilList.get(k).intValue() + "")) {
							BarabasiAlbertSequenceGenerator.getGraph().addEdge(victimList.get(index) ,
									sybilList.get(k).intValue() + "");
						/*	String victim = index + "";
							if (!victimList.contains(victim)) {
								victimList.add(victim);
							}
							*/
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
			BarabasiAlbertSequenceGenerator.birthSnapshot.put(sibil+"", BarabasiAlbertSequenceGenerator.num_snapshots);
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

	public void addVictims(int num_victims) {
		
		int newVictims = num_victims;
		Random rand = new Random();
		if(newVictims == -1) {
			newVictims = rand.nextInt(5);
		}
		ArrayList<String> victim2remove = new ArrayList<String>();
		for(String v: victimList) {
			if(!BarabasiAlbertSequenceGenerator.getGraph().vertexSet().contains(v)) {
				victim2remove.add(v);
				newVictims ++;
				this.victimCount --;
			}
		}
		for(String v: victim2remove)
			victimList.remove(v);
		ArrayList<String> vertexList = new ArrayList<String>(BarabasiAlbertSequenceGenerator.getGraph().vertexSet());

			//added by Xihui
		for (int j = 0; j <  newVictims; j++) {
			String fingerprint = null;
			do {
				fingerprint = Integer.toBinaryString(random.nextInt((int) Math.pow(2, this.attackerCount) - 1) + 1);
				while (fingerprint.length() < this.attackerCount)
					fingerprint = "0" + fingerprint;
			} while (fingerprints.containsKey(fingerprint));
			fingerprintKeys.add(fingerprint);
			fingerprints.put(fingerprint, fingerprint);

			int newvictimPos = rand.nextInt(vertexList.size());
			String newVictim = vertexList.get(newvictimPos);
			while (victimList.contains(newVictim) || newVictim.startsWith("-")) {
				newvictimPos = rand.nextInt(vertexList.size());
				newVictim = vertexList.get(newvictimPos);
			}
			victimList.add(newVictim);
			this.victimTargetedFrom.put(newVictim, BarabasiAlbertSequenceGenerator.num_snapshots-1);

			for (int k = 0; k < fingerprint.length(); k++) {
				if (fingerprint.charAt(k) == '1') {
/*					BarabasiAlbertSequenceGenerator.getGraph().addEdge(j + "",
							Integer.toString(sybilList.get(k).intValue()) + "");
					String victim = j + "";
					if (!victimList.contains(victim)) {
						victimList.add(victim);
					}
					*/
					BarabasiAlbertSequenceGenerator.getGraph().addEdge(newVictim,
							Integer.toString(sybilList.get(k).intValue()) + "");
				}
			}
		}
		this.victimCount = this.victimCount + newVictims;
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
					if (BarabasiAlbertSequenceGenerator.getGraph().containsEdge(Integer.toString(sybilList.get(k).intValue()) + "", 
							(victimList.get(importantPos)))) {
						// do nothing
					} else {
						BarabasiAlbertSequenceGenerator.getGraph().addEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) );
/*						String victim = importantPos+ "";
						if (!victimList.contains(victim)) {
							victimList.add(victim);
						}
						*/
					}
				} else if (newKey.charAt(k) == '0') {
					if (BarabasiAlbertSequenceGenerator.getGraph().containsEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "")) {
						BarabasiAlbertSequenceGenerator.getGraph().removeEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "");
					}
				}
			}
		}
	}

	public probResult currentSuccessProbability_attack0(Graph<String, DefaultEdge> originalGraph, 
			SimpleGraph<String, DefaultEdge> noisyGraph,
			Graph<String, DefaultEdge> previousGraph, 
			boolean isIntersectUsed, boolean isFlippedFingerprintActive) {
		
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

		if (isIntersectUsed){
			if(originalCurrentCandidates0_intersect.isEmpty()){
				candidates = getPotentialAttackerCandidates(sybilVertexDegrees, sybilVertexLinks,noisyGraph);
				originalCurrentCandidates0_intersect = candidates;
			}else{
				candidates_initial = getPotentialAttackerCandidates(sybilVertexDegrees, sybilVertexLinks, noisyGraph);
				if(candidates_initial.isEmpty()){
					return new probResult();
				}
				candidates = getIntersectedCandidatesList(originalCurrentCandidates0_intersect, candidates_initial, previousGraph);

				if(candidates.isEmpty()){
					// do nothing
				}else{
					originalCurrentCandidates0_intersect = candidates;
				}
			}
		}else {
			candidates = getPotentialAttackerCandidates(sybilVertexDegrees, sybilVertexLinks, noisyGraph);
			originalCurrentCandidates0_noIntersect = candidates;
			if (originalCurrentCandidates0_noIntersect.isEmpty())
				return new probResult();
		}

		/*
		 * Trujillo- Feb 4, 2016 Now, for every victim, we obtain the original
		 * fingerprint and look for the subset S of vertices with the same fingerprint.
		 * - If the subset is empty, then the success probability is 0 - If the subset
		 * is not empty, but the original victim is not in S, then again the probability
		 * of success is 0 - Otherwise the probability of success is 1/|S|
		 */
		
		
		/*
		 * probDistVictims is used to record the distribution of each victims through the entire attack.
		 */
		probDistVictims.clear();
		for(int i = 0; i<victimList.size(); i++)
			probDistVictims.add(new HashMap<String, Double>());

		probResult sumPartialSuccessProbs = new probResult() ;
		for (String[] candidate : candidates) {
			ArrayList<Set<String>> victimCandSets = new ArrayList<Set<String>>();
			Set<String> candSet = new HashSet<String>(Arrays.asList(candidate));

			for (int victim = 0; victim < victimList.size(); victim++) {
				
				Set<String> matchOfVictim = new HashSet<String>();

				//calculate the original fingerprint
				String originalFingerprint = getFingerprintOfOneVictim(victim, originalGraph);

				//Go though all pseduonymised vertex to find exact match.

				for (String vertex : noisyGraph.vertexSet()) {
					//boolean vertInCandidate = false;
					
					if (candSet.contains(vertex))
						continue;

					boolean isFound = true;
					for (int i = 0; isFound && i < candidate.length; i++) {
						if (noisyGraph.containsEdge(candidate[i], vertex) && originalFingerprint.charAt(i)!='1') 
							isFound = false;
						else if (!noisyGraph.containsEdge(candidate[i], vertex) && originalFingerprint.charAt(i)!='0')
							isFound = false;
					}
					
					if (isFound) 
						matchOfVictim.add(vertex);
				}
				victimCandSets.add(matchOfVictim);

			}

			/*
			 * Trujillo- Feb 9, 2016 For each candidate we sum its probability of success.
			 * The total probability is the average
			 */
			probResult prob_result = this.calSuccessProbForCandidate(victimCandSets);
			updatePartialSuccessProbs(sumPartialSuccessProbs, prob_result);
		}
	
		if (sumPartialSuccessProbs.getSumProb() - 0 > 0.000000001) {

			flipSpecificFingerPrint(getWeakestFingerprint(), isFlippedFingerprintActive);
			sumPartialSuccessProbs.setSumProb(sumPartialSuccessProbs.getSumProb()/getCorrectList_0(isIntersectUsed).size());
			sumPartialSuccessProbs.setMaxProb(sumPartialSuccessProbs.getMaxProb()/getCorrectList_0(isIntersectUsed).size());
			sumPartialSuccessProbs.setMatchProb(sumPartialSuccessProbs.getMatchProb()/getCorrectList_0(isIntersectUsed).size());

			probabilities.add(sumPartialSuccessProbs);
			allProbabilities.add(sumPartialSuccessProbs);
		}
		snapshotInformation = new  SnapshotInformation(BarabasiAlbertSequenceGenerator.getGraph(),
				noisyGraph, finalVictimList, sybilList, getCorrectList_0(isIntersectUsed));

		return sumPartialSuccessProbs;

	}
	
	/* attack1 uses robust sybil retrieval but exact matching*/

	public probResult currentSuccessProbability_attack1(Graph<String, DefaultEdge> originalGraph, SimpleGraph<String, DefaultEdge> noisyGraph,
			Graph<String, DefaultEdge> previousGraph,
			boolean isIntersectUsed,
			boolean isFlippedFingerprintActive) {
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
			if(originalCurrentCandidates1_intersect.isEmpty()){
				candidates = getPotentialAttackerCandidatesBFS(sybilVertexDegrees, sybilVertexLinks,noisyGraph,true);
				originalCurrentCandidates1_intersect = candidates;
			}else{
				candidates_initial = getPotentialAttackerCandidatesBFS(sybilVertexDegrees, sybilVertexLinks, noisyGraph,true);
				if(candidates_initial.isEmpty()){
					return new probResult();
				}
				candidates = getIntersectedCandidatesList(originalCurrentCandidates1_intersect, candidates_initial, previousGraph);
				if(candidates.isEmpty()){

				}else{
					originalCurrentCandidates1_intersect = candidates;
				}
			}

			if (originalCurrentCandidates1_intersect.isEmpty())
				return new probResult();
		}else {
			candidates = getPotentialAttackerCandidatesBFS(sybilVertexDegrees, sybilVertexLinks,noisyGraph,true);
			originalCurrentCandidates1_noIntersect = candidates;
			if (originalCurrentCandidates1_noIntersect.isEmpty())
				return new probResult();
		}

		/*
		 * Trujillo- Feb 4, 2016 Now, for every victim, we obtain the original
		 * fingerprint and look for the subset S of vertices with the same fingerprint.
		 * - If the subset is empty, then the success probability is 0 - If the subset
		 * is not empty, but the original victim is not in S, then again the probability
		 * of success is 0 - Otherwise the probability of success is 1/|S|
		 */

		probResult sumPartialSuccessProbs = new probResult();
		/*
		 * probDistVictims is used to record the distribution of each victims through the entire attack.
		 */
		probDistVictims.clear();
		for(int i = 0; i<victimList.size(); i++)
			probDistVictims.add(new HashMap<String, Double>());
		
		/* attack start from here */
		for (String[] candidate : getCorrectList_1(isIntersectUsed)) {

			ArrayList<Set<String>> victimCandSets = new ArrayList<Set<String>>();
			Set<String> candSet = new HashSet<String>(Arrays.asList(candidate));

			for (int victim = 0; victim < victimList.size(); victim++) {

				/* first obtain the original fingerprint */

				Set<String> matchOfVictim = new HashSet<String>();

				
				String originalFingerprint = getFingerprintOfOneVictim(victim, originalGraph);

				for (String vertex : noisyGraph.vertexSet()) {
					
					if (candSet.contains(vertex))
						continue;
					
					/* calculate the fingerprint of the vertex*/
					boolean isFound = true;
					for (int i = 0; isFound && i < candidate.length; i++) {
						if (noisyGraph.containsEdge(candidate[i], vertex) && originalFingerprint.charAt(i)!='1') 
							isFound = false;
						else if (!noisyGraph.containsEdge(candidate[i], vertex) && originalFingerprint.charAt(i)!='0')
							isFound = false;
					}
					
					if (isFound) 
						matchOfVictim.add(vertex);

				}
				victimCandSets.add(matchOfVictim);				
			}

			probResult prob_result = this.calSuccessProbForCandidate(victimCandSets);
			updatePartialSuccessProbs(sumPartialSuccessProbs, prob_result);
		}

		
		if (sumPartialSuccessProbs.getSumProb() - 0 > 0.000000001) {

			flipSpecificFingerPrint(getWeakestFingerprint(), isFlippedFingerprintActive);
			sumPartialSuccessProbs.setSumProb(sumPartialSuccessProbs.getSumProb()/getCorrectList_1(isIntersectUsed).size());
			sumPartialSuccessProbs.setMaxProb(sumPartialSuccessProbs.getMaxProb()/getCorrectList_1(isIntersectUsed).size());
			sumPartialSuccessProbs.setMatchProb(sumPartialSuccessProbs.getMatchProb()/getCorrectList_1(isIntersectUsed).size());

			probabilities.add(sumPartialSuccessProbs);
			allProbabilities.add(sumPartialSuccessProbs);
		}
		snapshotInformation = new  SnapshotInformation(BarabasiAlbertSequenceGenerator.getGraph(),
				noisyGraph,
				finalVictimList, sybilList, getCorrectList_1(isIntersectUsed));

		return sumPartialSuccessProbs;
	}

	public List<String[]> getSybilNetworkCandidates(Graph<String, DefaultEdge> originalGraph, 
			SimpleGraph<String, DefaultEdge> noisyGraph, Graph<String, DefaultEdge> previousGraph, boolean isIntersectUsed){
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
				candidates = getPotentialAttackerCandidatesBFS(sybilVertexDegrees, sybilVertexLinks,noisyGraph,isIntersectUsed);
				originalCurrentCandidates2_intersect = candidates;
			}else{
				candidates_initial = getPotentialAttackerCandidatesBFS(sybilVertexDegrees, sybilVertexLinks, noisyGraph,isIntersectUsed);
				if(candidates_initial.isEmpty()){
					return candidates_initial;
				}
				candidates = getIntersectedCandidatesList(originalCurrentCandidates2_intersect, candidates_initial,previousGraph);
				//if(candidates.isEmpty()){
				//}else{
				originalCurrentCandidates2_intersect = candidates;
				//}
			}
			//if (originalCurrentCandidates2_intersect.isEmpty())
			//	return null;

		} else {
			candidates = getPotentialAttackerCandidatesBFS(sybilVertexDegrees, sybilVertexLinks,noisyGraph,isIntersectUsed);
			originalCurrentCandidates2_noIntersect = candidates;
			//if (originalCurrentCandidates2_noIntersect.isEmpty())
			//	return null;
		}
		return candidates;
	}
	
	public probResult currentSuccessProbability_attack2(Graph<String, DefaultEdge> originalGraph, SimpleGraph<String, DefaultEdge> noisyGraph,
			Graph<String, DefaultEdge> previousGraph,
			boolean applyApproxFingerprintMatching, boolean isIntersectUsed, boolean isFlippedFingerprintActive) {

		/*calculate the sybil network candidates and stored in 
		 * originalCurrentCandidates2_noIntersect/Intersect. If no candidats are found, return 0 
		 */

		ArrayList<String> copyVictimList = new ArrayList<String> ();
		for (int i=0; i<victimList.size(); i++){
			copyVictimList.add(i,victimList.get(i));
		}

		ArrayList<Integer> copySybilList = new ArrayList<Integer> ();
		for (int i=0; i<sybilList.size(); i++){
			copySybilList.add(i,sybilList.get(i));
		}
		this.maxEditDistance = (int) Math.min(1500, 16+ 250*Math.pow((BarabasiAlbertSequenceGenerator.num_snapshots-2),2));
//		this.maxEditDistance = 250;
		this.BFS1StartTime = System.currentTimeMillis();
		this.timeout = false;
		
		List<String[]> candidates = this.getSybilNetworkCandidates(originalGraph, noisyGraph, previousGraph, isIntersectUsed);
		
		System.out.println("Elapse time is " + (System.currentTimeMillis() - this.BFS1StartTime)/1000d);

		if(candidates.isEmpty()) {
			
			System.out.println("candidateList is empty");
			snapshotInformation = new  SnapshotInformation(BarabasiAlbertSequenceGenerator.cloneGraph(
					BarabasiAlbertSequenceGenerator.getGraph()),
					noisyGraph,
				copyVictimList, copySybilList, cloneList(candidates));
			return new probResult();
		}
		

		/*  probDistVictims is used to record the distribution of each victims through the entire attack. */
		probDistVictims.clear();
		for(int i = 0; i<victimList.size(); i++)
			probDistVictims.add(new HashMap<String, Double>());

		probResult sumPartialSuccessProbs = new probResult();

		this.BFS1StartTime = System.currentTimeMillis();
		this.timeout = false;
		
		System.out.println("Started constructing sequences ...");

		//calculate the original fingerprints
		int maxTargetedFrom = 0;
		ArrayList<String> originalFingerprints = new ArrayList<>();
		
		for (int victim = 0; victim < victimList.size(); victim++) {
				String originalFingerprint = getFingerprintOfOneVictim(victim, originalGraph);
				originalFingerprints.add(originalFingerprint);
				if(this.victimTargetedFrom.get(victimList.get(victim))>maxTargetedFrom)
					maxTargetedFrom = this.victimTargetedFrom.get(victimList.get(victim));
			}

		for (String[] candidate : getCorrectList_2(isIntersectUsed)) {

			//Stores all the vertices that is possibly mapped to the victims
			ArrayList<Set<String>> victimCandSets = new ArrayList<Set<String>>();
			Set<String> candSet = new HashSet<String>(Arrays.asList(candidate));

			if (applyApproxFingerprintMatching) {

				// We first find all the existing exact matchings, because no approximate search
				// needs to be done for them

				// Compute all fingerprints of all pseudonymised vertices 
				HashMap<String, String> allFingerprints = new HashMap<>();
				for (String v : noisyGraph.vertexSet()) {
					if(BarabasiAlbertSequenceGenerator.birthSnapshot.get(v)>maxTargetedFrom)
						continue;
					String pvFingerprint = "";

					for (int i = 0; i < sybilList.size(); i++)
						if (noisyGraph.containsEdge(v, candidate[i]))
							pvFingerprint += "1";
						else
							pvFingerprint += "0";

					if (pvFingerprint.indexOf("1") != -1)
						allFingerprints.put(v, pvFingerprint);
				}


				Set<Integer> exactlyMatchedVictims = new HashSet<>();
				//first try exact matching
				for (int victim = 0; victim < victimList.size(); victim++) {

					int targetedFrom = this.victimTargetedFrom.get(victimList.get(victim));
					//added by xihui to implement a naive timer
					if ((System.currentTimeMillis()-this.BFS1StartTime)/1000d>this.timeLimit) {
						this.timeout= true;
						return sumPartialSuccessProbs;
					}
					Set<String> matchOfVictim = new HashSet<String>();//stores the possible vertices mapped to the victim

					String originalFingerprint = originalFingerprints.get(victim);
				
					FingerprintSimilarity fsim = new FSimCoincidenceCount();
					int maxSim = -1;
					for (String v : noisyGraph.vertexSet()) {
						
						if(BarabasiAlbertSequenceGenerator.birthSnapshot.get(v)>targetedFrom)
							continue;
						if(!allFingerprints.containsKey(v))
							continue;
						
						int sim = fsim.similarity(originalFingerprint, allFingerprints.get(v));
						if (sim > maxSim) {
							maxSim = sim;
							matchOfVictim.clear();
							matchOfVictim.add(v);
						} else if ((sim == maxSim)&& !matchOfVictim.contains(v)) {
							matchOfVictim.add(v);
						}
					}
					if(matchOfVictim.isEmpty()) {
					}else
						exactlyMatchedVictims.add(victim);
					
					victimCandSets.add(matchOfVictim);
				}

				System.out.println("Mapping construction done. Start calculating probabilities ...");
				probResult prob_result = this.calSuccessProbForCandidate(victimCandSets);

				System.out.println("Done. Start updating probabilities ...");
				updatePartialSuccessProbs(sumPartialSuccessProbs, prob_result);
				System.out.println("Done. Start the rest ...");
			} else {

				// We will apply exact fingerprint matching, which will be based on Rolando's
				// implementation

				for (int victim = 0; victim < victimList.size(); victim++) {

					Set<String> matchOfVictim = new HashSet<String>();
					String originalFingerprint = originalFingerprints.get(victim);

					for (String vertex : noisyGraph.vertexSet()) {
						if(candSet.contains(vertex))
							continue;
						
						boolean isFound = true;
						for (int i = 0; isFound && i < candidate.length; i++) {
							if (noisyGraph.containsEdge(candidate[i], vertex) && originalFingerprint.charAt(i)!='1') 
								isFound = false;
							else if (!noisyGraph.containsEdge(candidate[i], vertex) && originalFingerprint.charAt(i)!='0')
								isFound = false;
						}
					
						if (isFound) 
							matchOfVictim.add(vertex);
					}

					victimCandSets.add(matchOfVictim);
				}
				probResult prob_result = this.calSuccessProbForCandidate(victimCandSets);
				updatePartialSuccessProbs(sumPartialSuccessProbs, prob_result);
			}
		}
		
		//if(isIntersectUsed)
		
			snapshotInformation = new  SnapshotInformation(BarabasiAlbertSequenceGenerator.cloneGraph(BarabasiAlbertSequenceGenerator.getGraph()),
					noisyGraph,
				copyVictimList, copySybilList, cloneList(getCorrectList_2(isIntersectUsed)));
		
		if (sumPartialSuccessProbs.getSumProb() - 0 > 0.000000001) {
			if (isIntersectUsed)
				flipSpecificFingerPrint(getWeakestFingerprint(), isFlippedFingerprintActive);
			sumPartialSuccessProbs.setSumProb(sumPartialSuccessProbs.getSumProb()/getCorrectList_2(isIntersectUsed).size());
			sumPartialSuccessProbs.setMaxProb(sumPartialSuccessProbs.getMaxProb()/getCorrectList_2(isIntersectUsed).size());
			sumPartialSuccessProbs.setMatchProb(sumPartialSuccessProbs.getMatchProb()/getCorrectList_2(isIntersectUsed).size());
			probabilities.add(sumPartialSuccessProbs);
			allProbabilities.add(sumPartialSuccessProbs);
		}

		return sumPartialSuccessProbs;
	}

	
	public void updatePartialSuccessProbs(probResult partialProb, probResult currentProb) {
		partialProb.setMatchProb(partialProb.getMatchProb() + currentProb.getMatchProb());
		partialProb.setMaxProb(partialProb.getMaxProb() + currentProb.getMaxProb());
		partialProb.setSumProb(partialProb.getSumProb() + currentProb.getSumProb());
	}

	protected List<String[]> getPotentialAttackerCandidates(int[] fingerprintDegrees, boolean[][] fingerprintLinks, 
			SimpleGraph<String, DefaultEdge> noisyGraph) {
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

	protected List<String[]> getPotentialAttackerCandidatesBFS(int[] fingerprintDegrees, boolean[][] fingerprintLinks,
			SimpleGraph<String, DefaultEdge> noisyGraph, boolean checkConsistency) {

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

					//edited by Xihui to add a naive timer
					
					
					int glbDist = getPotentialAttackerCandidatesBFS1(fingerprintDegrees, fingerprintLinks, noisyGraph,
							currentPartialCandidate, returnedPartialCandidates, checkConsistency);
					
					if (this.timeout)
						return finalCandidates;
					if (glbDist < minGlbDistValue) {
						//minGlbDistValue = glbDist;
						candidatesMinGlb.clear();
						candidatesMinGlb.addAll(returnedPartialCandidates);
					} //else if (glbDist == minGlbDistValue)
					candidatesMinGlb.addAll(returnedPartialCandidates);
				}

				for (List<String> cand : candidatesMinGlb)
					finalCandidates.add(cand.toArray(new String[cand.size()]));
			}

		return finalCandidates;
	}

	protected int getPotentialAttackerCandidatesBFS1(int[] fingerprintDegrees, boolean[][] fingerprintLinks,SimpleGraph<String, DefaultEdge> noisyGraph,
			List<String> currentPartialCandidate, List<List<String>> partialCandidates2Return, 
			boolean checkConsistency) {

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
						newCand, checkConsistency);

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
					//edited by xihui to set the timer
					long currentTime = System.currentTimeMillis();
//					if ((currentTime - this.BFS1StartTime)/1000d > this.timeLimit ) {
					if ((currentTime - this.BFS1StartTime)/1000d > this.timeLimit ) {
						this.timeout = true;
						return minGlbDistValue;
					}
					
					List<String> newCurrentPartialCandidate = new ArrayList<>(currentPartialCandidate);
					newCurrentPartialCandidate.add(v);
					List<List<String>> returnedPartialCandidates = new ArrayList<>();
					int glbDist = getPotentialAttackerCandidatesBFS1(fingerprintDegrees, fingerprintLinks,noisyGraph,
							newCurrentPartialCandidate, returnedPartialCandidates,checkConsistency);
					//Xihui
					/*if (glbDist < minGlbDistValue) {
						minGlbDistValue = glbDist;
						candidatesMinGlb.clear();
						candidatesMinGlb.addAll(returnedPartialCandidates);
					} else if (glbDist == minGlbDistValue)*/
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


	protected int edgeEditDistanceWeaklyInduced(SimpleGraph<String, DefaultEdge> noisyGraph, List<String> vertSet1,	
			List<String> vertSet2, boolean checkConsistency) {

		if (vertSet1.size() == vertSet2.size()) {
			if(checkConsistency) {
				boolean sameBirth = true;
				for(int i = 0; sameBirth && i<vertSet1.size(); i++) {
					String v1 = vertSet1.get(i);
					String v2 = vertSet2.get(i);
					int birthV1 = -1;
					if (BarabasiAlbertSequenceGenerator.birthSnapshot.containsKey(v1))
						birthV1 = BarabasiAlbertSequenceGenerator.birthSnapshot.get(v1);
					else {
						System.out.println("the birth snapshot of v1 is not found.");
					}
					int birthV2 = -1; 
					if (BarabasiAlbertSequenceGenerator.birthSnapshot.containsKey(v2))
						birthV2 = BarabasiAlbertSequenceGenerator.birthSnapshot.get(v2);
					else {
						System.out.println("the birth snapshot of v2 is not found.");
					}
					if(birthV1 != birthV2)
						sameBirth = false;
					}
			
				if (!sameBirth)
					return 1 + (noisyGraph.vertexSet().size()
						* (noisyGraph.vertexSet().size() - 1)) / 2; 
			}
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

	@Override
	public void createInitialAttackerSubgraph(int attackerCount, int victimCount) {
		// TODO Auto-generated method stub

	}

	public List<String[]> getIntersectedCandidatesList(List<String[]> original, List<String[]> current_new, 
			Graph<String, DefaultEdge> previousGraph) {

		if (previousGraph == null )
			return current_new;

		if (original.isEmpty()) return current_new;

		if(original.get(0).length > current_new.get(0).length) return current_new;
		
		int existingSybilSize = original.get(0).length;

		List<String[]> consistentCands = new ArrayList<String[]>();
		for (String[] strings2 : current_new) {
			boolean isConsistent = true;
			for (String[] strings : original) {
				for (int i = 0; isConsistent && i<existingSybilSize; i++) {
					if(!strings2[i].equalsIgnoreCase(strings[i]))
						isConsistent = false;
				}
				if(isConsistent) {
					consistentCands.add(strings2);
					break;
				}
				isConsistent = true;
			}
		}
		if (consistentCands.isEmpty())
			return current_new;
		else
			return consistentCands;
	}

	protected FingerprintSetMatchingReturnValue approxFingerprintMatching(
			Map<String, String> fingerprintsPossibleVictims, List<String> originalFingerprints,
			Set<Integer> matchedOrigFingerprints, int attackerCount) {
		FingerprintSimilarity fsim = new FSimCoincidenceCount();

		// Find all choices for the next match. Each choice is a pair (yi,v) where yi is
		// a real victim.
		int maxSim = (int)(1.75 * this.attackerCount);
		
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

	/*
	 * return the index of the victim which has the largest entropy
	 */
	protected int getWeakestFingerprint() {

		if (probDistVictims.isEmpty()) 
			return -1;
		
		double minEnt = Double.MAX_VALUE;
		int index_with_minEnt = 0;
		
		for (int i = 0; i < probDistVictims.size(); i++) {
			double ent = 0;
			for(double p : probDistVictims.get(i).values()) {
				ent += (p*(Math.log(p)/Math.log(2)));
			}
			if(ent < minEnt) {
				minEnt = ent;
				index_with_minEnt = i;
			}
		}
		
		return index_with_minEnt;
		
			
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
					if (BarabasiAlbertSequenceGenerator.getGraph().containsEdge(Integer.toString(sybilList.get(k).intValue()) + "", 
							(victimList.get(importantPos)))) {
						// do nothing
					} else {
						BarabasiAlbertSequenceGenerator.getGraph().addEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) );
/*						String victim = importantPos+ "";
						if (!victimList.contains(victim)) {
							victimList.add(victim);
						}
						*/
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
					/*	String victim = importantPos+ "";
						if (!victimList.contains(victim)) {
							victimList.add(victim);
						}
						*/
					}
				} else if (newKey.charAt(k) == '0') {
					if (BarabasiAlbertSequenceGenerator.getGraph().containsEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "")) {
						BarabasiAlbertSequenceGenerator.getGraph().removeEdge(Integer.toString(sybilList.get(k).intValue()) + "", (victimList.get(importantPos)) + "");
					}
				}
			}
		} 
	}
	private String getFingerprintOfOneVictim(int victim, Graph<String, DefaultEdge> originalGraph) {

		String originalFingerprint = "";
		for (int i = 0; i < this.attackerCount; i++) {
			if (originalGraph.containsEdge(sybilList.get(i) + "", victimList.get(victim) + ""))
				originalFingerprint += "1";
			else
				originalFingerprint += "0";
		}
		return originalFingerprint;
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

	private probResult calSuccessProbForCandidate(ArrayList<Set<String>> victimSets) {
		probResult prob; 
		int totalCorrect = 0;
		
		ArrayList<String> partialMatching = new ArrayList<String>();
		ArrayList<ArrayList<String>> matchList = new ArrayList<ArrayList<String>>(); 
		calProbPartialMatching(partialMatching, 0, victimSets, totalCorrect, matchList) ;
		
		if(!matchList.isEmpty()) {
			prob = updateProbability(matchList);
			//prob = 1.0 * totalCorrect /matchList.size();
		}else
			prob = new probResult();

		return prob;
	}

    private probResult calSuccessProbForCandidate(ArrayList<Set<String>> victimSets,
    	ArrayList<Map<Integer, String>> approMatchings) {
		probResult prob; 
		int totalCorrect = 0;
		
		ArrayList<String> partialMatching = new ArrayList<String>();
		ArrayList<ArrayList<String>> matchList = new ArrayList<ArrayList<String>>(); 
		calProbPartialMatching(partialMatching, victimSets, approMatchings, totalCorrect, matchList) ;
		
		if(!matchList.isEmpty()) {
			prob = updateProbability(matchList);
		}else {
			prob = new probResult();
		}
		return prob;
	}

	private probResult updateProbability(ArrayList<ArrayList<String>> matchList) {
		double sumprob = 0d;
		double matchprob = 0d;
		if (matchList.isEmpty())
			return new probResult();
		int maxMatch = 0;
		for (ArrayList<String> matching : matchList) {
			int match_num = 0;
			for (int i = 0; i<matching.size(); i++) {
				String vCand = matching.get(i);
				double currProb = 0; 
				if (probDistVictims.get(i).containsKey(vCand))
					currProb = probDistVictims.get(i).get(vCand);
				probDistVictims.get(i).put(vCand, currProb + 1.0/matchList.size());
				if (matching.get(i).equalsIgnoreCase(victimList.get(i))) {
					sumprob +=1.0;
					match_num ++;
				}
			}
			if(match_num == victimList.size())
				matchprob = 1.0;

			if(match_num > maxMatch)	
				maxMatch = match_num;
		}
		probResult result = new probResult();
		result.setMatchProb(matchprob/(matchList.size()));
		result.setMaxProb(maxMatch*1.0/victimList.size());
		result.setSumProb(sumprob/(matchList.size()*victimList.size()));
		
		return result;
	}
	private void calProbPartialMatching(ArrayList<String> pm, int correctNum, ArrayList<Set<String>> victimSets,
			int totalCorrect, ArrayList<ArrayList<String>> matchList) {
		int startFrom = pm.size();
		Set<String> S = victimSets.get(startFrom);
		
		if (S.isEmpty())
			S.add("-1");
		//the naive timer
		for(String victim : S) {
			if ((System.currentTimeMillis()-this.BFS1StartTime)/1000d> this.timeLimit  ) {
				this.timeout= true;
				return ;
			}
			if(pm.contains(victim))
				continue;
			pm.add(victim);
			int currentCorrectNum = correctNum;
			
			if(victim.equalsIgnoreCase(victimList.get(startFrom)))
				currentCorrectNum ++;
			
			if(pm.size() == victimList.size()) {
				ArrayList<String> newmatch = new ArrayList<String>();
				//Modified by Xihui
				//for (String s : pm)
				boolean birthConsistency = true;
				for(int i=0; birthConsistency && i<pm.size(); i++) {
					String s = pm.get(i);
					if(s!="-1" && BarabasiAlbertSequenceGenerator.birthSnapshot.get(s)>
					this.victimTargetedFrom.get(victimList.get(i))) 
						birthConsistency = false;
					else
						newmatch.add(s);
				}
				if (birthConsistency)
					matchList.add(newmatch);
				if (matchList.size()>1000) 
					break;
				totalCorrect += currentCorrectNum;
			}else {
				this.calProbPartialMatching(pm, currentCorrectNum, victimSets, totalCorrect, matchList);
			}
			pm.remove(startFrom);
		}
	}

	private void calProbPartialMatching(ArrayList<String> pm, ArrayList<Set<String>> victimSets,
			ArrayList<Map<Integer, String>> approMatchings,
			int totalCorrect, ArrayList<ArrayList<String>> matchList) {

		//if(approMatchings.isEmpty())
		//	return;

		int startFrom = pm.size();
		Set<String> S;
		if (!approMatchings.isEmpty() && approMatchings.get(0).containsKey(startFrom)){
			S = new HashSet<String>();
			S.add("-1");
		}else
			S = victimSets.get(startFrom);
		
		if (S.isEmpty())
			//return;
			S.add("-2");
		for(String victim : S) {
			if(!victim.equalsIgnoreCase("-1") && !victim.equalsIgnoreCase("-2") && (pm.contains(victim)))
				//||BarabasiAlbertSequenceGenerator.birthSnapshot.get(victimList.get(startFrom))!=
				//					BarabasiAlbertSequenceGenerator.birthSnapshot.get(victim)))
				continue;
		
			pm.add(victim);
			
			if(pm.size() == victimList.size()) {
				for(Map<Integer,String> partialMatching : approMatchings) {
					ArrayList<String> newmatch = new ArrayList<String>();
					boolean successMatch = true;
					int correctVm = 0;
					for(int i = 0; successMatch && i<pm.size(); i++) {
						String s = pm.get(i);
						if (s.equalsIgnoreCase("-1")) {
							s = partialMatching.get(i);
							/*if(newmatch.contains(s)||
									BarabasiAlbertSequenceGenerator.birthSnapshot.get(victimList.get(i))!=
									BarabasiAlbertSequenceGenerator.birthSnapshot.get(s)) 
								successMatch = false;*/
						}
						if(s.equalsIgnoreCase(victimList.get(i)))
								correctVm ++;
						newmatch.add(s);
					}
					if(successMatch) {
						matchList.add(newmatch);
						totalCorrect += correctVm;
					}
				}
			}else {
				this.calProbPartialMatching(pm, victimSets, approMatchings, totalCorrect, matchList);
			}
			pm.remove(startFrom);

		}
	}
	

	public probResult refineReIdentification(Graph<String, DefaultEdge> originalGraph, 
			SimpleGraph<String, DefaultEdge> noisyGraph,
			List<String> victimList, List<Integer> sybilList, List<String[]> candidates) {
		
		
		this.maxEditDistance = (int) Math.min(1500, 16+ 350*Math.pow((BarabasiAlbertSequenceGenerator.num_snapshots-2),2));
//		this.maxEditDistance = 250;
		this.BFS1StartTime = System.currentTimeMillis();
		this.timeout = false;
		
		//System.out.println("Elapse time is " + (System.currentTimeMillis() - this.BFS1StartTime)/1000d);

		if(candidates.isEmpty()) {
			System.out.println("candidateList is empty");
			return new probResult();
		}
		

		/*  probDistVictims is used to record the distribution of each victims through the entire attack. */
		probDistVictims.clear();
		for(int i = 0; i<victimList.size(); i++)
			probDistVictims.add(new HashMap<String, Double>());

		probResult sumPartialSuccessProbs = new probResult();

		this.BFS1StartTime = System.currentTimeMillis();
		this.timeout = false;
		
		System.out.println("Started constructing sequences ...");

		//calculate the original fingerprints
		ArrayList<String> originalFingerprints = new ArrayList<>();
		for (int victim = 0; victim < victimList.size(); victim++) {
				String originalFingerprint = getFingerprintOfOneVictim(victim, originalGraph, victimList, sybilList);
				originalFingerprints.add(originalFingerprint);
		}

		int validCandidate =0 ;
		for (String[] candidate : candidates) {
			
			boolean last_use_consistent = true;
			for(int i =0; i<candidate.length && last_use_consistent; i++) {
				String sybil = sybilList.get(i)+"";
				if(BarabasiAlbertSequenceGenerator.diedSnapshot.containsKey(sybil) &&
						BarabasiAlbertSequenceGenerator.diedSnapshot.get(sybil)==
						BarabasiAlbertSequenceGenerator.num_snapshots-1) {
					if(!BarabasiAlbertSequenceGenerator.diedSnapshot.containsKey(candidate[i])||
							BarabasiAlbertSequenceGenerator.diedSnapshot.get(candidate[i])!= BarabasiAlbertSequenceGenerator.num_snapshots-1)
						last_use_consistent = false;
				}
			}

			if (!last_use_consistent) 
				continue;
			else
				validCandidate ++;

			//Stores all the vertices that is possibly mapped to the victims
			ArrayList<Set<String>> victimCandSets = new ArrayList<Set<String>>();
			Set<String> candSet = new HashSet<String>(Arrays.asList(candidate));


			HashMap<String, String> allFingerprints = new HashMap<>();
			for (String v : noisyGraph.vertexSet()) {
				String pvFingerprint = "";
				for (int i = 0; i < sybilList.size(); i++)
					if (noisyGraph.containsEdge(v, candidate[i]))
						pvFingerprint += "1";
					else
						pvFingerprint += "0";

				if (pvFingerprint.indexOf("1") != -1)
					allFingerprints.put(v, pvFingerprint);
			}


			Set<Integer> exactlyMatchedVictims = new HashSet<>();

			//first try exact matching
			for (int victim = 0; victim < victimList.size(); victim++) {

					int targetedFrom = this.victimTargetedFrom.get(victimList.get(victim));
					//added by xihui to implement a naive timer
					if ((System.currentTimeMillis()-this.BFS1StartTime)/1000d>this.timeLimit) {
						this.timeout= true;
						return sumPartialSuccessProbs;
					}
					Set<String> matchOfVictim = new HashSet<String>();//stores the possible vertices mapped to the victim

					String originalFingerprint = originalFingerprints.get(victim);
				
					FingerprintSimilarity fsim = new FSimCoincidenceCount();
					int maxSim = -1;
					for (String v : noisyGraph.vertexSet()) {
						
						if(BarabasiAlbertSequenceGenerator.birthSnapshot.get(v)>targetedFrom || !allFingerprints.containsKey(v))
							continue;
						
						if(BarabasiAlbertSequenceGenerator.diedSnapshot.containsKey(victimList.get(victim)) && 
								BarabasiAlbertSequenceGenerator.diedSnapshot.get(victimList.get(victim))==
								BarabasiAlbertSequenceGenerator.num_snapshots-1) {
							if(!BarabasiAlbertSequenceGenerator.diedSnapshot.containsKey(v) 
							 || BarabasiAlbertSequenceGenerator.diedSnapshot.get(v)!= 
									BarabasiAlbertSequenceGenerator.num_snapshots-1)
								continue;
						}
						
						int sim = fsim.similarity(originalFingerprint, allFingerprints.get(v));
						if (sim > maxSim) {
							maxSim = sim;
							matchOfVictim.clear();
							matchOfVictim.add(v);
						} else if ((sim == maxSim)&& !matchOfVictim.contains(v)) {
							matchOfVictim.add(v);
						}
					}
					victimCandSets.add(matchOfVictim);
				}

				System.out.println("Mapping construction done. Start calculating probabilities ...");
				probResult prob_result = this.calSuccessProbForCandidate(victimCandSets, victimList);

				System.out.println("Done. Start updating probabilities ...");
				updatePartialSuccessProbs(sumPartialSuccessProbs, prob_result);
				System.out.println("Done. Start the rest ...");
	}
		
		
		if (sumPartialSuccessProbs.getSumProb() - 0 > 0.000000001 && validCandidate > 0) {
			sumPartialSuccessProbs.setSumProb(sumPartialSuccessProbs.getSumProb()/validCandidate);
			sumPartialSuccessProbs.setMaxProb(sumPartialSuccessProbs.getMaxProb()/validCandidate);
			sumPartialSuccessProbs.setMatchProb(sumPartialSuccessProbs.getMatchProb()/validCandidate);
			probabilities.add(sumPartialSuccessProbs);
			allProbabilities.add(sumPartialSuccessProbs);
		}

		return sumPartialSuccessProbs;
	}

	private probResult calSuccessProbForCandidate(ArrayList<Set<String>> victimSets, List<String> victimList ) {
		probResult prob; 
		int totalCorrect = 0;
		
		ArrayList<String> partialMatching = new ArrayList<String>();
		ArrayList<ArrayList<String>> matchList = new ArrayList<ArrayList<String>>(); 
		calProbPartialMatching(partialMatching, 0, victimSets, victimList, totalCorrect, matchList) ;
		
		if(!matchList.isEmpty()) {
			prob = updateProbability(matchList, victimList);
			//prob = 1.0 * totalCorrect /matchList.size();
		}else
			prob = new probResult();

		return prob;
	}
	
	private void calProbPartialMatching(ArrayList<String> pm, int correctNum, ArrayList<Set<String>> victimSets,
		List<String> victimList,
			int totalCorrect, ArrayList<ArrayList<String>> matchList) {
		int startFrom = pm.size();
		Set<String> S = victimSets.get(startFrom);
		
		if (S.isEmpty())
			S.add("-1");
		//the naive timer
		for(String victim : S) {
			if ((System.currentTimeMillis()-this.BFS1StartTime)/1000d> this.timeLimit  ) {
				this.timeout= true;
				return ;
			}
			if(pm.contains(victim))
				continue;
			pm.add(victim);
			int currentCorrectNum = correctNum;
			
			if(victim.equalsIgnoreCase(victimList.get(startFrom)))
				currentCorrectNum ++;
			
			if(pm.size() == victimList.size()) {
				//System.out.println("checkpoint 1, to be removed afterward ..");
				ArrayList<String> newmatch = new ArrayList<String>();
				//Modified by Xihui
				//for (String s : pm)
				for(int i=0; i<pm.size(); i++) {
					String s = pm.get(i);
					newmatch.add(s);
				}
				matchList.add(newmatch);
				totalCorrect += currentCorrectNum;
			}else {
				this.calProbPartialMatching(pm, currentCorrectNum, victimSets,victimList, totalCorrect, matchList);
			}
			pm.remove(startFrom);
		}
	}
	private probResult updateProbability(ArrayList<ArrayList<String>> matchList,List<String> victimList) {
		double sumprob = 0d;
		double matchprob = 0d;
		if (matchList.isEmpty())
			return new probResult();
		int maxMatch = 0;
		for (ArrayList<String> matching : matchList) {
			int match_num = 0;
			for (int i = 0; i<matching.size(); i++) {
				String vCand = matching.get(i);
				double currProb = 0; 
				if (probDistVictims.get(i).containsKey(vCand))
					currProb = probDistVictims.get(i).get(vCand);
				probDistVictims.get(i).put(vCand, currProb + 1.0/matchList.size());
				if (matching.get(i).equalsIgnoreCase(victimList.get(i))) {
					sumprob +=1.0;
					match_num ++;
				}
			}
			if(match_num == victimList.size())
				matchprob = 1.0;

			if(match_num > maxMatch)	
				maxMatch = match_num;
		}
		probResult result = new probResult();
		result.setMatchProb(matchprob/(matchList.size()));
		result.setMaxProb(maxMatch*1.0/victimList.size());
		result.setSumProb(sumprob/(matchList.size()*victimList.size()));
		
		return result;
	}
	
	List<String[]> cloneList(List<String[]> list2){
		List<String[]> list = new ArrayList<String[]> ();
		for (String[] v: list2) {
			String [] v1 = new String[v.length];
			for(int i=0; i<v.length; i++)
				v1[i] = v[i];
			list.add(v1);
		}
		return list;
	}

	private String getFingerprintOfOneVictim(int victim, Graph<String, DefaultEdge> originalGraph, List<String> victimList,
			List<Integer> sybilList) {

		String originalFingerprint = "";
		for (int i = 0; i < sybilList.size(); i++) {
			if (originalGraph.containsEdge(sybilList.get(i) + "", victimList.get(victim) + ""))
				originalFingerprint += "1";
			else
				originalFingerprint += "0";
		}
		return originalFingerprint;
	}

}
