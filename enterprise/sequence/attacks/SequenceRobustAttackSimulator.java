package enterprise.sequence.attacks;

import java.math.RoundingMode;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jgrapht.Graph;
import org.jgrapht.UndirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;

import com.google.common.math.LongMath;

import enterprise.sequence.generators.BarabasiAlbertSequenceGenerator;
import enterprise.sequence.generators.Controller;
import util.FSimCoincidenceCount;
import util.FingerprintSimilarity;

public class SequenceRobustAttackSimulator extends enterprise.sequence.attacks.SybilAttackSimulatorMe {
	
	
	protected class FingerprintSetMatchingReturnValue {
		public Set<Map<Integer, String>> matches; 
		public int maxSimilarity;
		public FingerprintSetMatchingReturnValue(Set<Map<Integer, String>> matches, int maxSimilarity) {
			this.matches = matches;
			this.maxSimilarity = maxSimilarity;
		}
	}
	
	
	SecureRandom random = new SecureRandom();
	
	protected int maxEditDistance;
	protected boolean applySybilDegSeqOptimization;

	protected boolean applyApproxFingerprintMatching;
	protected ArrayList<Integer> sybilList = new ArrayList<Integer>();
	protected Hashtable<String, String> fingerprints = new Hashtable<>();
	protected ArrayList<String> fingerprintKeys = new ArrayList<String>();
	protected ArrayList<String> victimList = new ArrayList<String>();
	protected Set<String> uniformlyDistributedFingerprints;
	protected boolean generateOnceUnifDistrFp;
	protected int attackerCountOfGeneratedUnifDistrFp; 
	protected int victimCountOfGeneratedUnifDistrFp;
	protected int initialIinterations;
	
	protected int attackerCount, victimCount;
	
    //Case 1: We only use this and nothing else
	Controller controller = new Controller();
	ArrayList<Graph<String, DefaultEdge>> snapshotList = controller.getSnapshotList();
	
	ArrayList<Double> probabilities = new ArrayList<Double>();
	ArrayList<Double> allProbabilities = new ArrayList<Double>();
	
	public SequenceRobustAttackSimulator(int maxEditDist, boolean sybDegSeqOpt, boolean apprFgPrMatch) {
		maxEditDistance = maxEditDist;
		applySybilDegSeqOptimization = sybDegSeqOpt;
	
		uniformlyDistributedFingerprints = null;
		generateOnceUnifDistrFp = false;
		attackerCountOfGeneratedUnifDistrFp = -1;
		victimCountOfGeneratedUnifDistrFp = -1;
		applyApproxFingerprintMatching = apprFgPrMatch;
		maxEditDistance = 4;
		long vertexNumber= BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size();
		attackerCount=LongMath.log2( vertexNumber, RoundingMode.UP);
	}
	
	@Override
	public void createInitialAttackerSubgraph(int attackerCount, int victimCount) {
		System.out.println("You just created an initial attackG on the graph.");
		System.out.println("When evolving the graph you can only send three values as parameters");
		System.out.println("1 - Add sybils");
		System.out.println("2 - Add victims");
		System.out.println("3 - Flip connections");
		/* The BarabasiAlbertSequenceGenerator.getGraph() is assumed to satisfy all requirements, notably vertices being labeled from attackerCount on, 
		 * and connectivity if required
		 */
		
		this.attackerCount = attackerCount;
		this.victimCount = victimCount;
			
		if (victimCount == 0)
			victimCount = 1;
		
		if (attackerCount + victimCount > BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size())
			victimCount = BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size() - attackerCount;
		
		int sibil = -1;
		for (int j = 0; j < attackerCount; j++) {
			BarabasiAlbertSequenceGenerator.getGraph().addVertex(sibil+"");//it's adding attackers
			sybilList.add(Integer.valueOf(sibil));
			sibil--;
		}
		
		
		initialIinterations = (attackerCount + victimCount) - attackerCount;
		
		loopToAddEdgesWithSybilsAndVictims:
		for (int j = 0; j < initialIinterations; j++) {
			String fingerprint = null;
			do {
				fingerprint = Integer.toBinaryString(random.nextInt((int)Math.pow(2, attackerCount)-1) + 1);
				while (fingerprint.length() < attackerCount)
					fingerprint = "0" + fingerprint;
			
			} while (fingerprints.containsKey(fingerprint));
			fingerprintKeys.add(fingerprint);
			fingerprints.put(fingerprint, fingerprint);
			
			for (int k = 0; k < fingerprint.length(); k++) {
				if (fingerprint.charAt(k) == '1'){
					// Check and break the loop when the number of victims if bigger then sybils
					BarabasiAlbertSequenceGenerator.getGraph().addEdge(j+"", Integer.toString(sybilList.get(k).intValue()) +"");
					String victim = j+"";
					if(!victimList.contains(victim)) {
						victimList.add(victim);
					}
				}
			}
		}

		if (attackerCount > 1) {
			for (int k = 0; k < attackerCount - 1; k++) {
				BarabasiAlbertSequenceGenerator.getGraph().addEdge(Integer.toString(sybilList.get(k).intValue()) +"", Integer.toString(sybilList.get(k+1).intValue())+"");
			}
		}
		
		//Connect all sybils with each other with 50% chance
		for(int i = 0; i < sybilList.size(); i++) {
			for(int j = 0; j < sybilList.size()-1; j++) {
				if(random.nextBoolean()) {
					if((sybilList.get(i)+"").equals(sybilList.get(j+1)+"")){	
					}else {
						if(!BarabasiAlbertSequenceGenerator.getGraph().containsEdge(sybilList.get(i)+"", sybilList.get(j+1)+"")){
							BarabasiAlbertSequenceGenerator.getGraph().addEdge(sybilList.get(i)+"", sybilList.get(j+1)+"");
						}
					}
				}
			}
		}
		
	}


	@Override
	public void evolveAttackerSubgraph(int attackerCount, int victimCount, int choice) {
		// TODO Auto-generated method stub
		
	}
	public double currentSuccessProbability_attack2(Graph<String, DefaultEdge> originalGraph) {
		int[] sybilVertexDegrees = new int[this.attackerCount];
		boolean[][] sybilVertexLinks = new boolean[this.attackerCount][this.attackerCount];
		
		for (int i = 0; i < this.attackerCount; i++) {
			// Attackers are assumed to be the first attackerCount vertices in the graph, because of the manner in which the attack was simulated 
			int index=sybilList.get(i);
			int deg= originalGraph.degreeOf(index+"");
			sybilVertexDegrees[i] = deg;
		}
		
		for (int i = 0; i < this.attackerCount; i++) {
			for (int j = 0; j < this.attackerCount; j++) {
				if (originalGraph.containsEdge(i + "", j + ""))
					sybilVertexLinks[i][j] = true;
				else 
					sybilVertexLinks[i][j] = false;
			}
		}
		
		List<String[]> candidates = getPotentialAttackerCandidatesBFS(sybilVertexDegrees, sybilVertexLinks);  
		
		if (candidates.isEmpty()) 
			return 0;   
		
		double sumPartialSuccessProbs = 0;
		for (String[] candidate : candidates) { 
			
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
				
				// We first find all the existing exact matchings, because no approximate search needs to be done for them
				
				/*
				 * put the sybil nodes in canAsSet
				 */
				Set<String> candAsSet = new HashSet<>();
				for (String cv : candidate)
					candAsSet.add(cv);
				
				// Compute all fingerprints
				HashMap<String, String> allFingerprints = new HashMap<>();
				for (String v : originalGraph.vertexSet()) {
					String pvFingerprint = "";
					for (int i = 0; i < this.attackerCount; i++)
						if (originalGraph.containsEdge(v, candidate[i]))
							pvFingerprint += "1";
						else
							pvFingerprint += "0";
					/**
					 * In an initial implementation, we were decoding the fingerprint for correcting possible errors.
					 * Now, we only use the encoding to increase edit-distance, but do not attempt to decode at this step 
					 */
					//pvFingerprint = codec.correctedCodeWord(pvFingerprint);
					if (pvFingerprint.indexOf("1") != -1)
						allFingerprints.put(v, pvFingerprint);
				}
				
				Set<Integer> exactlyMatchedVictims = new HashSet<>();
				boolean exactMatchFailed = false;
				
				for (int victim = 0; victim < victimList.size(); victim++) {
					int bucketSizeVictim = 0;
					boolean victimInBucket = false;
					for (String v : originalGraph.vertexSet()) 
						if (!candAsSet.contains(v) && allFingerprints.containsKey(v) && allFingerprints.containsKey("" + victim) && allFingerprints.get("" + victim).equals(allFingerprints.get(v))) {
							bucketSizeVictim++;
							if (v.equals("" + victim)) {
								victimInBucket = true;
								exactlyMatchedVictims.add(victim);
							}
							allFingerprints.remove(v);   // This will no longer be a potential candidate for approximate matchings
						}
					if (bucketSizeVictim > 0) {
						if (victimInBucket)
							successProbForCandidate *= 1d / (double)bucketSizeVictim;
						else { 
							successProbForCandidate = 0d;
							exactMatchFailed = true;
							break;
						}
					}
				}
				
				if (!exactMatchFailed && exactlyMatchedVictims.size() < originalFingerprints.size()) 
					if (originalFingerprints.size() - exactlyMatchedVictims.size() <= allFingerprints.size()) {
						
						//FingerprintSetMatchingReturnValue matchingResult = approxFingerprintMatching(anonymizedGraph, candidate, allFingerprints, originalFingerprints, matchedVictims);
						FingerprintSetMatchingReturnValue matchingResult = approxFingerprintMatching(allFingerprints, originalFingerprints, exactlyMatchedVictims, this.attackerCount);
						
						if (matchingResult.maxSimilarity <= 0)
							successProbForCandidate = 0d;
						else
							successProbForCandidate *= 1d / (double)matchingResult.matches.size();
						
					}
					else   // The remaining fingerprints are too few for the remaining unmatched victims 
						successProbForCandidate = 0d;
			}
			else {
				
				// We will apply exact fingerprint matching, which will be based on Rolando's implementation
				
				for (int victim = 0; victim < victimList.size(); victim++) {
					
					int cardinalityOfTheSubset = 0;
					boolean victimInsideSubset = false;
					for (String vertex : originalGraph.vertexSet()) {
						String tmpFingerprint = "";
						boolean vertInCandidate = false;
						for (int i = 0; !vertInCandidate && i < candidate.length; i++) {
							if (vertex.equals(candidate[i]))
								vertInCandidate = true;
							else if (originalGraph.containsEdge(candidate[i], vertex))
								tmpFingerprint += "1";
							else
								tmpFingerprint += "0";
						}
						if (!vertInCandidate) {
							/**
							 * In an initial implementation, we were decoding the fingerprint for correcting possible errors.
							 * Now, we only use the encoding to increase edit-distance, but do not attempt to decode at this step 
							 */
							//if (useErrorCorrectingFingerprints)
								//tmpFingerprint = codec.correctedCodeWord(tmpFingerprint);
							if (tmpFingerprint.equals(originalFingerprints.get(victim))) {
								cardinalityOfTheSubset++;
								if (victim == Integer.parseInt(vertex))
									victimInsideSubset = true;
							}
						}
					}
					
					/* As implemented by Rolando, the probability to identify this victim 
					 * is either 0 or 1/cardinalityOfTheSubset
					 * The total probability of identifying all victims is the product
					 * While the probability becomes 0 if at least one victim cannot be identified*/
					
					if (cardinalityOfTheSubset != 0 && victimInsideSubset && successProbForCandidate != 0)
						successProbForCandidate *= 1d / cardinalityOfTheSubset;
					else
						successProbForCandidate = 0;
				}
			}
			
			// For each candidate we sum its probability of success. The total probability is the average
			sumPartialSuccessProbs += successProbForCandidate;
		}
		return sumPartialSuccessProbs / candidates.size();
	}
	protected List<String[]> getPotentialAttackerCandidatesBFS(int[] fingerprintDegrees, boolean[][] fingerprintLinks) {
		
		int minLocDistValue = 1 + (BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size() * (BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size() - 1)) / 2;   // One more than the maximal possible distance (the total amount of edges). This is "positive infinity" in this context.
		Set<String> vertsMinDistValue = new HashSet<>();
		for (String v : BarabasiAlbertSequenceGenerator.getGraph().vertexSet()) {
			int dist = Math.abs(fingerprintDegrees[0] -BarabasiAlbertSequenceGenerator.getGraph().degreeOf(v));   // If called, the function edgeEditDistanceWeaklyInduced would return this value. We don't to avoid creating the singleton lists
			if (dist < minLocDistValue) {
				minLocDistValue = dist;
				vertsMinDistValue.clear();
				vertsMinDistValue.add(v);
			}
			else if (dist == minLocDistValue)
				vertsMinDistValue.add(v);
		}
		
		List<String[]> finalCandidates = new ArrayList<>();
		
		if (minLocDistValue <= maxEditDistance) 
			if (fingerprintDegrees.length == 1) 
				for (String v : vertsMinDistValue)
					finalCandidates.add(new String[]{v});
			else {   // fingerprintDegrees.length > 1
				
				// Explore recursively
				int minGlbDistValue = 1 + (BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size() * (BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size() - 1)) / 2;   // One more than the maximal possible distance (the total amount of edges). This is "positive infinity" in this context.
				List<List<String>> candidatesMinGlb = new ArrayList<>();
				for (String v : vertsMinDistValue) {
					List<String> currentPartialCandidate = new ArrayList<>();
					currentPartialCandidate.add(v);
					List<List<String>> returnedPartialCandidates = new ArrayList<>();
					int glbDist = getPotentialAttackerCandidatesBFS(fingerprintDegrees, fingerprintLinks,  currentPartialCandidate, returnedPartialCandidates);
					if (glbDist < minGlbDistValue) {
						minGlbDistValue = glbDist;
						candidatesMinGlb.clear();
						candidatesMinGlb.addAll(returnedPartialCandidates);
					}
					else if (glbDist == minGlbDistValue)
						candidatesMinGlb.addAll(returnedPartialCandidates);
				}
				
				for (List<String> cand : candidatesMinGlb)
					finalCandidates.add(cand.toArray(new String[cand.size()]));
			}
		
		return finalCandidates;
	}
	protected int getPotentialAttackerCandidatesBFS(int[] fingerprintDegrees, boolean[][] fingerprintLinks, List<String> currentPartialCandidate, List<List<String>> partialCandidates2Return) {
		
		int minLocDistValue = 1 + (BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size() * (BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size() - 1)) / 2;   // One more than the maximal possible distance (the total amount of edges). This is "positive infinity" in this context.
		Set<String> vertsMinDistValue = new HashSet<>();
		
		List<String> currentSybPrefix = new ArrayList<>();
		for (int i = 0; i < currentPartialCandidate.size() + 1; i++) {
			int index=sybilList.get(i);
			currentSybPrefix.add("" + index);
			}
		for (String v :BarabasiAlbertSequenceGenerator.getGraph().vertexSet()) 
			if (!currentPartialCandidate.contains(v)) {
			
				List<String> newCand = new ArrayList<>(currentPartialCandidate);
				newCand.add(v);
				
				int dist = edgeEditDistanceWeaklyInduced(BarabasiAlbertSequenceGenerator.getGraph(), currentSybPrefix, newCand);
				
				if (dist < minLocDistValue) {
					minLocDistValue = dist;
					vertsMinDistValue.clear();
					vertsMinDistValue.add(v);
				}
				else if (dist == minLocDistValue)
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
				int minGlbDistValue = 1 + (BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size() * BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size() - 1) / 2;   // One more than the maximal possible distance (the total amount of edges). This is "positive infinity" in this context.
				List<List<String>> candidatesMinGlb = new ArrayList<>();
				for (String v : vertsMinDistValue) {
					List<String> newCurrentPartialCandidate = new ArrayList<>(currentPartialCandidate);
					newCurrentPartialCandidate.add(v);
					List<List<String>> returnedPartialCandidates = new ArrayList<>();
					int glbDist = getPotentialAttackerCandidatesBFS(fingerprintDegrees, fingerprintLinks, newCurrentPartialCandidate, returnedPartialCandidates);
					if (glbDist < minGlbDistValue) {
						minGlbDistValue = glbDist;
						candidatesMinGlb.clear();
						candidatesMinGlb.addAll(returnedPartialCandidates);
					}
					else if (glbDist == minGlbDistValue)
						candidatesMinGlb.addAll(returnedPartialCandidates);
				}
				
				partialCandidates2Return.addAll(candidatesMinGlb);
				return minGlbDistValue;
			}
		else   // minLocDistValue > maxEditDistance
			return 1 + (BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size() * (BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size() - 1)) / 2;   // One more than the maximal possible distance (the total amount of edges). This is "positive infinity" in this context.
	}
	
	
	protected FingerprintSetMatchingReturnValue approxFingerprintMatching(UndirectedGraph<String, DefaultEdge> anonymizedGraph, String[] candidateSybilVerts, HashMap<String, String> fingerprintsPossibleVictims, ArrayList<String> originalFingerprints, Set<Integer> matchedOrigFingerprints) {
		
		FingerprintSimilarity fsim = (FingerprintSimilarity) new FSimCoincidenceCount();
				
		// Find all choices for the first match. Each choice is a pair (yi,v) where yi is a real victim.
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
					}
					else if (sim == maxSim) {
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
		
		if (originalFingerprints.size() == 1) {   // No more matches to do after this one
			for (Integer ordOrigFP : bestLocalMatches.keySet()) { 
				for (String v : bestLocalMatches.get(ordOrigFP)) {
					Map<Integer, String> entry = new HashMap<>();
					entry.put(ordOrigFP, v);
					allMatches.add(entry);
				}				
			}
			return new FingerprintSetMatchingReturnValue(allMatches, maxSim);
		}
		else {   // originalFingerprints.size() > 1. Go recursively
			
			int maxSimRestOfMatching = -1;
			
			for (Integer ordOrigFP : bestLocalMatches.keySet())
				for (String pv : bestLocalMatches.get(ordOrigFP)) {
					Set<Integer> newMatchedOrigFingerprints = new HashSet<>();
					newMatchedOrigFingerprints.add(ordOrigFP);
					HashMap<String, String> fingerprintsRemainingPossibleVictims = new HashMap<>(fingerprintsPossibleVictims);
					fingerprintsRemainingPossibleVictims.remove(pv);
					
					FingerprintSetMatchingReturnValue resultRemainingMatching = approxFingerprintMatching(fingerprintsRemainingPossibleVictims, originalFingerprints, newMatchedOrigFingerprints, candidateSybilVerts.length);
					
					if (resultRemainingMatching.maxSimilarity > maxSimRestOfMatching) {
						maxSimRestOfMatching = resultRemainingMatching.maxSimilarity;
						allMatches.clear();
						for (Map<Integer, String> mms : resultRemainingMatching.matches) {
							mms.put(ordOrigFP, pv);
							allMatches.add(mms);
						}
					}
					else if (resultRemainingMatching.maxSimilarity == maxSimRestOfMatching) 
						for (Map<Integer, String> mms : resultRemainingMatching.matches) {
							mms.put(ordOrigFP, pv);
							allMatches.add(mms);
						}
				}
			
			if (maxSimRestOfMatching <= 0)
				return new FingerprintSetMatchingReturnValue(allMatches, -1);
			else 
				return new FingerprintSetMatchingReturnValue(allMatches, maxSimRestOfMatching);
			}
	}

	protected FingerprintSetMatchingReturnValue approxFingerprintMatching(Map<String, String> fingerprintsPossibleVictims, List<String> originalFingerprints, Set<Integer> matchedOrigFingerprints, int attackerCount) {
		
		FingerprintSimilarity fsim = (FingerprintSimilarity) new FSimCoincidenceCount();
		
		// Find all choices for the next match. Each choice is a pair (yi,v) where yi is a real victim.
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
					}
					else if (sim == maxSim) {
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
		
		if (maxSim == -1)   // This happens if there were too few available fingerprints 
			return new FingerprintSetMatchingReturnValue(allMatches, -1);
		
		if (matchedOrigFingerprints.size() + 1 < originalFingerprints.size()) {   // Recursion can continue at least one more level from here 
			
			int maxSimRestOfMatching = -1;
			
			for (Integer ordOrigFP : bestLocalMatches.keySet())
				for (String pv : bestLocalMatches.get(ordOrigFP)) {
					Set<Integer> newMatchedOrigFingerprints = new HashSet<>();
					newMatchedOrigFingerprints.add(ordOrigFP);
					HashMap<String, String> fingerprintsRemainingPossibleVictims = new HashMap<>(fingerprintsPossibleVictims);
					fingerprintsRemainingPossibleVictims.remove(pv);
					
					FingerprintSetMatchingReturnValue resultRemainingMatching = approxFingerprintMatching(fingerprintsRemainingPossibleVictims, originalFingerprints, newMatchedOrigFingerprints, attackerCount);
					
					if (resultRemainingMatching.maxSimilarity != -1) {
						if (resultRemainingMatching.maxSimilarity > maxSimRestOfMatching) {
							maxSimRestOfMatching = resultRemainingMatching.maxSimilarity;
							allMatches.clear();
							for (Map<Integer, String> mms : resultRemainingMatching.matches) {
								mms.put(ordOrigFP, pv);
								allMatches.add(mms);
							}
						}
						else if (resultRemainingMatching.maxSimilarity == maxSimRestOfMatching) 
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
			
		}
		else {   // Recursion stops when matchedOrigFingerprints.size() == originalFingerprints.size() - 1, that is, we are doing the last matching  
			boolean realVictimMatched = false;
			for (Integer ordOrigFP : bestLocalMatches.keySet()) { 
				for (String v : bestLocalMatches.get(ordOrigFP)) {
					Map<Integer, String> entry = new HashMap<>();
					entry.put(ordOrigFP, v);
					allMatches.add(entry);
					if (v.equals("" + attackerCount + ordOrigFP))
						realVictimMatched = true;
				}
			}
			if (realVictimMatched)
				return new FingerprintSetMatchingReturnValue(allMatches, maxSim);
			else
				return new FingerprintSetMatchingReturnValue(allMatches, -1);
		}		
	}
	protected int edgeEditDistanceWeaklyInduced(Graph<String, DefaultEdge> graph, List<String> vertSet1, List<String> vertSet2) {
		if (vertSet1.size() == vertSet2.size()) {
			int diffCount = 0;
			List<Integer> externalDegrees1 = new ArrayList<>();
			List<Integer> externalDegrees2 = new ArrayList<>();
			for (int i = 0; i < vertSet1.size(); i++) {
				externalDegrees1.add(BarabasiAlbertSequenceGenerator.getGraph().degreeOf(vertSet1.get(i)));
				externalDegrees2.add(BarabasiAlbertSequenceGenerator.getGraph().degreeOf(vertSet2.get(i)));
			}
			for (int i = 0; i < vertSet1.size() - 1; i++) 
				for (int j = i + 1; j < vertSet1.size(); j++) 
					if (BarabasiAlbertSequenceGenerator.getGraph().containsEdge(vertSet1.get(i), vertSet1.get(j))) {
						externalDegrees1.set(i, externalDegrees1.get(i) - 1);
						if (BarabasiAlbertSequenceGenerator.getGraph().containsEdge(vertSet2.get(i), vertSet2.get(j))) 
							externalDegrees2.set(i, externalDegrees2.get(i) - 1);
						else
							diffCount++;
					}
					else   // !BarabasiAlbertSequenceGenerator.getGraph().containsEdge(vertSet1.get(i), vertSet1.get(j))
						if (BarabasiAlbertSequenceGenerator.getGraph().containsEdge(vertSet2.get(i), vertSet2.get(j))) {
							diffCount++;
							externalDegrees2.set(i, externalDegrees2.get(i) - 1);
						}
						// else !BarabasiAlbertSequenceGenerator.getGraph().containsEdge(vertSet2.get(i), vertSet2.get(j))
			
			int dist = diffCount;
			for (int i = 0; i < vertSet1.size(); i++)
				dist += Math.abs(externalDegrees1.get(i) - externalDegrees2.get(i));
						
			return dist;
		}
		return 1 + (BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size() * (BarabasiAlbertSequenceGenerator.getGraph().vertexSet().size() - 1)) / 2;   // One more than the maximal possible distance (the total amount of edges). This is "positive infinity" in this context. 
	}
	
	public double currentSuccessProbability(int attackerCount, int victimCount,
			UndirectedGraph<String, DefaultEdge> graph, UndirectedGraph<String, DefaultEdge> originalGraph) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public double updateSuccessProbabilities(int attackerCount, int victimCount,
			UndirectedGraph<String, DefaultEdge> graph, UndirectedGraph<String, DefaultEdge> originalGraph) {
		// TODO Auto-generated method stub
		return 0;
	}
	public Graph<String, DefaultEdge> getGraphAfterEvolve(){
		return BarabasiAlbertSequenceGenerator.getGraph();      
	}
	public static void main(String [] args) {
		/*
		 * set the parameters of the graph generator
		 * graph will grow by nodes by default
		 */
		BarabasiAlbertSequenceGenerator<String, DefaultEdge> sequenceGenerator = new BarabasiAlbertSequenceGenerator<String, DefaultEdge>(10,3, 100);
		/*
		 * create the first social graph with the parameters 
		 */
		sequenceGenerator.initialize(1);
		
		/* create the attacker object */
		SequenceRobustAttackSimulator robustAttackSimulator= new SequenceRobustAttackSimulator(2, false, false);
		
		/* create the first sybil network */
		robustAttackSimulator.createInitialAttackerSubgraph(5,10);
		
		/* generate the first noisy graph */
		
		SimpleGraph<String, DefaultEdge> anonymousGraph = sequenceGenerator.getNoisyGraph(0.05, BarabasiAlbertSequenceGenerator.getGraph());
//		sequenceGenerator.makeSnapshot(0.05);
		double successProbability_1stRun = robustAttackSimulator.currentSuccessProbability_attack2(BarabasiAlbertSequenceGenerator.getGraph());
		System.out.println("1st run: "+ successProbability_1stRun);
		double successProbability_2ndRun = robustAttackSimulator.currentSuccessProbability_attack2(BarabasiAlbertSequenceGenerator.getGraph());
		System.out.println("2nd run: "+ successProbability_1stRun);
	}
}
