package enterprise.sequence.attacks;


import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import enterprise.sequence.attacks.sybilAttackDynamicSimulator.probResult;

import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;

import attacks.SnapshotInformation;
import enterprise.sequence.generators.BarabasiAlbertSequenceGenerator;
import enterprise.sequence.generators.GraphStatisiticsGenerator;

public class Experiment {

	public static void main(String[] args) throws IOException {
       Experiment exp = new Experiment();
/*
       int num_exe = Integer.parseInt(args[0]);
       int edgesPerNode = Integer.parseInt(args[1]);
       int vertexNumFirstSnapshot = Integer.parseInt(args[2]);
       int initialVictimNum = Integer.parseInt(args[3]);
       int snapshotNum = Integer.parseInt(args[4]);
       double growRateBetweenSnapshot = Double.parseDouble(args[5]);
       double noisePercentage = Double.parseDouble(args[6]);
       int attackConfig = Integer.parseInt(args[7]);
       int numNewVictimsPerSnapshot = Integer.parseInt(args[8]) ;
       int startFrom = Integer.parseInt(args[9])  ;
       */
       int num_exe = 100;
       int edgesPerNode = 5; //2, 5, 8, 10
       int vertexNumFirstSnapshot = 800;//1000, 3000, 4000
       int initialVictimNum = -1;
       int snapshotNum = 20;
       double growRateBetweenSnapshot = 5;
       double noisePercentage = 0.5;//0.5,1.0, 1.5, 2.0, 2.5, 5, 10
       int attackConfig = 2; // 1: LogN + Random number of new victims + weakestFlip 
       //2: LogN + Random number of new victims + random Flip 
       int numNewVictimsPerSnapshot = -1; // -1 means add a random number of victims
       int startFrom = 1;

       exp.executeExperiment(num_exe, 30, edgesPerNode, vertexNumFirstSnapshot, initialVictimNum, 
    		   snapshotNum,growRateBetweenSnapshot, noisePercentage, attackConfig, 
    		   numNewVictimsPerSnapshot,startFrom);


       

/*       
      int initialVictimNum = Integer.parseInt(args[0]);
       double noisePercentage = Double.parseDouble(args[1]);
       int attackConfig = Integer.parseInt(args[2]);
        int numNewVictimsPerSnapshot = Integer.parseInt(args[3]) ;
       int startFrom = Integer.parseInt(args[4])  ;
 
*/
/*       
       int initialVictimNum = -1;
       double noisePercentage = 0.5; 
       int attackConfig = 1;
      int numNewVictimsPerSnapshot = -1;
       int startFrom = 1;

*/
/*       
       String nodeMappingFile = "nodemapMathoverflowEach.txt"; 

       exp. executeExperimentRGMathoverflowInteractionGraph(initialVictimNum, noisePercentage, numNewVictimsPerSnapshot, 
    		   nodeMappingFile, startFrom);

*/
       /*
	   String nodeMappingFile = "nodemapbitcoin.txt"; 
	   String graphFile = "bitcoinGraphs.txt";
	   */

/*       exp.executeExperimentRGMathoverflow(initialVictimNum, noisePercentage, numNewVictimsPerSnapshot, 
    		   nodeMappingFile, graphFile, startFrom);
*/

/*       exp.executeExperimentRGMathoverflow(initialVictimNum, noisePercentage, numNewVictimsPerSnapshot, 
	   String nodeMappingFile = "petsterNodeMapping6month.txt"; 
	   String graphFile = "petsterGraphFile.txt";

       exp.executeExperimentRG(initialVictimNum, noisePercentage,attackConfig, numNewVictimsPerSnapshot,
   		   nodeMappingFile, graphFile, startFrom);
*/	
   }

	public void executeExperimentRG(int initialVictimCount, double percentageOfNoise, int attackConfiguration,
			int numNewVictimsPerSnapshot, String nodeMappingFile, String graphFile, int starting_snapshot)
			throws IOException {

		String graphStats = "";
		// Keep in mind that 'snapshotsPerGraph' should be divisible by
		// 'frequencyOfAverage'

		String fileName = "results/RealGraph_" + percentageOfNoise + "_" + initialVictimCount
				+ "_" + attackConfiguration + "_" + starting_snapshot + ".txt";
		FileWriter fw = new FileWriter(fileName, true);

		int num_victims = numNewVictimsPerSnapshot;
		for (int num_exe = 1; num_exe <= 100; num_exe++) {
			BarabasiAlbertSequenceGenerator<String, DefaultEdge> sequenceGenerator = new BarabasiAlbertSequenceGenerator<>();

			// the parameter 1 does not have any meaning
			int num_snapshots = sequenceGenerator.initializeRealGraph(nodeMappingFile, graphFile, "petster");
			SimpleGraph<String, DefaultEdge> noisyGraph = null;

			sybilAttackDynamicSimulator attackSimulator = new sybilAttackDynamicSimulator();

			// attackSimulator.createInitialAttackerSubgraph(initialVictimCount);

			probResult prob_result;

			for (int snapShotIndex = 0; snapShotIndex < num_snapshots; snapShotIndex++) {

				System.out.println("Start attacking the snapshot " + snapShotIndex + "...");
				if (snapShotIndex == 0) {
					noisyGraph = sequenceGenerator.getNoisyGraph(percentageOfNoise,
							BarabasiAlbertSequenceGenerator.getGraph());
				} else {
					int num_previousReleases;
					String outputStr;
					String fName;
					SnapshotInformation snapshotInfo2add;
					switch (attackConfiguration) {
					// Original attack by no_consistency, flip random fingerprint and random sybils
					case 1:

						if (snapShotIndex <= starting_snapshot) {
							snapshotInfo2add = new SnapshotInformation(BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph, null,null,
									null);
						} else
							snapshotInfo2add = attackSimulator.snapshotInformation;

						sequenceGenerator.makeSnapshot(nodeMappingFile, graphFile, snapshotInfo2add);

						if (snapShotIndex == starting_snapshot)
							attackSimulator.createInitialAttackerSubgraph(initialVictimCount);

						else if (snapShotIndex > starting_snapshot) {
							// attackSimulator.evolveAttackerSubgraph(0, 0, 2);
							attackSimulator.addVictims(num_victims);
							attackSimulator.evolveAttackerSubgraph(0, 0, 4);
						}

						// attackSimulator.graphEvolveByRemoval(percentageOfRemoval, sequenceGenerator);


						noisyGraph = sequenceGenerator.getNoisyGraph(percentageOfNoise,
								BarabasiAlbertSequenceGenerator.getGraph());

						if (snapShotIndex < starting_snapshot)
							break;

						 graphStats =
						 calculateGraphStatistics(BarabasiAlbertSequenceGenerator.getGraph(),
						 noisyGraph);

						fName = "RealGraph_" +num_exe + "_" + percentageOfNoise + "_" + initialVictimCount + "_"
								+ attackConfiguration + "_" + starting_snapshot + "_" + snapShotIndex + ".txt";

						//printGraph(BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph, fName);

						num_previousReleases = sequenceGenerator.getSnapshotInformtions().size();
						long startTime = System.currentTimeMillis();
						if (snapShotIndex == starting_snapshot)
							prob_result = attackSimulator.currentSuccessProbability_attack2(
									BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph,
									BarabasiAlbertSequenceGenerator.getGraph(), true, true, true);
						else
							prob_result = attackSimulator.currentSuccessProbability_attack2(
									BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph,
									sequenceGenerator.getSnapshotInformtions().get(num_previousReleases - 1).getGraph(),
									true, true, true);
						long endTime = System.currentTimeMillis();

						double elapsedTime = ((endTime - startTime) / 1000d);

						outputStr =num_exe+ " " + snapShotIndex + " " + prob_result.getMatchProb() + " " + prob_result.getMaxProb()
								+ " " + prob_result.getSumProb() + " " + attackSimulator.victimList.size() + " "
								+ attackSimulator.attackerCount + " " + elapsedTime + " " + graphStats + "\n";

						fw.write(outputStr);

						fw.flush();
						break;
					case 2:// consistency, random flip, random add
						if (snapShotIndex <= starting_snapshot) {
							snapshotInfo2add = new SnapshotInformation(BarabasiAlbertSequenceGenerator.getGraph(), 
									noisyGraph, null,null, null);
						} else
							snapshotInfo2add = attackSimulator.snapshotInformation;

						// attackSimulator.graphEvolveByRemoval(percentageOfRemoval, sequenceGenerator);

						sequenceGenerator.makeSnapshot(nodeMappingFile, graphFile, snapshotInfo2add);

						if (snapShotIndex == starting_snapshot)
							attackSimulator.createInitialAttackerSubgraph(initialVictimCount);
						else if (snapShotIndex > starting_snapshot) {
							// attackSimulator.evolveAttackerSubgraph(0, 0, 2);
							attackSimulator.addVictims(num_victims);
							attackSimulator.evolveAttackerSubgraph(0, 0, 4);
							attackSimulator.evolveAttackerSubgraph(0, 0, 3);
						}

						noisyGraph = sequenceGenerator.getNoisyGraph(percentageOfNoise,
								BarabasiAlbertSequenceGenerator.getGraph());

						if (snapShotIndex < starting_snapshot)
							break;

						if(snapShotIndex> starting_snapshot) {
                        	System.out.println("Refining re-identification ...");
                        	SnapshotInformation snapInfo = attackSimulator.snapshotInformation;	
                        	prob_result = attackSimulator.refineReIdentification(snapInfo.getGraph(), 
                        			snapInfo.getNoisyGraph(), snapInfo.getVictimList(), snapInfo.getSybilList(),snapInfo.getCandidateAttackersList());
                        	outputStr = num_exe + " " + (snapShotIndex-1) + " " + prob_result.getMatchProb() + " " + 
                        		prob_result.getMaxProb() + " " + prob_result.getSumProb()+"\n";
                        	fw.write(outputStr);
                        	fw.flush();
                        }
						//graphStats = calculateGraphStatistics(BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph);

						/*fName = "RealGraph_" + num_exe + "_" + percentageOfNoise + "_"
								+ initialVictimCount + "_" + attackConfiguration + "_"
								+ starting_snapshot + "_" + snapShotIndex + ".txt";

						printGraph(BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph, fName);
						*/

						num_previousReleases = sequenceGenerator.getSnapshotInformtions().size();
						startTime = System.currentTimeMillis();
						if (snapShotIndex == starting_snapshot)
							prob_result = attackSimulator.currentSuccessProbability_attack2(
									BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph,
									BarabasiAlbertSequenceGenerator.getGraph(), true, true, false);
						else
							prob_result = attackSimulator.currentSuccessProbability_attack2(
									BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph,
									sequenceGenerator.getSnapshotInformtions().get(num_previousReleases - 1).getGraph(),
									true, true, false);

						endTime = System.currentTimeMillis();
						elapsedTime = ((endTime - startTime) / 1000d);
						outputStr = num_exe+" " +snapShotIndex + " " + prob_result.getMatchProb() + " " + prob_result.getMaxProb()
								+ " " + prob_result.getSumProb() + " " + attackSimulator.victimList.size() + " "
								+ attackSimulator.attackerCount + " " + elapsedTime + " " + graphStats + "\n";

						fw.write(outputStr);

						fw.flush();
						break;
					}
				}
			}
		}
		fw.close();
	}
 
    private void executeExperiment(int numberOfGraphs, int initialNodes, int edgesPerNode, int finalNodes,
    		int initialVictimCount, int snapshotsPerGraph, double percentageOfAdditions, 
    		double percentageOfNoise, int attackConfiguration,int numNewVictimsPerSnapshot, int starting_snapshot) throws IOException {
/*
 * Class BarabasiAlberSequenceGenerator stores the graph at the moment
 * The variable SequenceGenerator stores all the previous snapshots and the results including the noisy graph. 
 */
       String graphStats= "";
        // Keep in mind that 'snapshotsPerGraph' should be divisible by 'frequencyOfAverage'

        String fileName = "results/Graph_" + finalNodes + "_"+ edgesPerNode + "_" + percentageOfNoise + "_" +
        initialVictimCount + "_" + percentageOfAdditions+ "_" + attackConfiguration + "_" + numNewVictimsPerSnapshot +
        "_"+starting_snapshot + ".txt";
        FileWriter fw = new FileWriter(fileName,true);

        int num_victims = numNewVictimsPerSnapshot;
        for (int num_exe = 1; num_exe <= numberOfGraphs; num_exe ++) { // 50 is number of graphsar
            // Clear lists

            BarabasiAlbertSequenceGenerator<String, DefaultEdge> sequenceGenerator = new 
            		BarabasiAlbertSequenceGenerator<>(initialNodes, edgesPerNode, finalNodes);
            // the parameter 1 does not have any meaning
            sequenceGenerator.initialize(1);
            SimpleGraph<String, DefaultEdge> noisyGraph = null;

            sybilAttackDynamicSimulator attackSimulator = new sybilAttackDynamicSimulator();

           // attackSimulator.createInitialAttackerSubgraph(initialVictimCount);

            probResult prob_result;

            for (int snapShotIndex = 0; snapShotIndex <=snapshotsPerGraph; snapShotIndex++) {

            	System.out.println("Start attacking " +" Graph_" + finalNodes + "_"+ edgesPerNode +"_" 
                		+ percentageOfNoise +"_" +initialVictimCount +
                		"_" + percentageOfAdditions+ " " + 
                		attackConfiguration + "_" + numNewVictimsPerSnapshot+"_"+starting_snapshot + "_"+ num_exe + "_"+ snapShotIndex );
            	if (snapShotIndex == 0) {
            		noisyGraph = sequenceGenerator.getNoisyGraph(percentageOfNoise, 
            			BarabasiAlbertSequenceGenerator.getGraph());
            	}else {
            		
            		int num_previousReleases;
					String outputStr;
					String fName ; 
                    SnapshotInformation snapshotInfo2add;
					switch (attackConfiguration) {
                // Original attack by no_consistency, flip random fingerprint and random sybils 
                    case 1:

                    	if(snapShotIndex <= starting_snapshot) {
                    		snapshotInfo2add = new SnapshotInformation(BarabasiAlbertSequenceGenerator.getGraph(),noisyGraph, null,null,null);
                    	}else
                    		snapshotInfo2add = attackSimulator.snapshotInformation;
                    	
                    	System.out.println("Start growing the sybil network ...");
                    	if(snapShotIndex==starting_snapshot)
                    		attackSimulator.createInitialAttackerSubgraph(initialVictimCount);
                    	else if (snapShotIndex>starting_snapshot){
                    		//attackSimulator.evolveAttackerSubgraph(0, 0, 2);
                    		attackSimulator.addVictims(num_victims); 
                    		attackSimulator.evolveAttackerSubgraph(0, 0, 4);
                    	}

                    	//attackSimulator.graphEvolveByRemoval(percentageOfRemoval, sequenceGenerator);

                    	System.out.println("Start making the snapshot ...");
                        sequenceGenerator.makeSnapshotByEdgePercentage(percentageOfAdditions, 
                        		snapshotInfo2add);                        

                    	System.out.println("Start making the noisy graph ...");
                        noisyGraph = sequenceGenerator.getNoisyGraph(percentageOfNoise, 
                        		BarabasiAlbertSequenceGenerator.getGraph());
                        if(snapShotIndex <starting_snapshot)
                        	break;

                        graphStats = calculateGraphStatistics(BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph);
                        
                        /*fName = "Graph_" + finalNodes + "_"+ edgesPerNode +"_" 
                        		+ percentageOfNoise +"_" +initialVictimCount +
                        		"_" + percentageOfAdditions+ " " + 
                        		attackConfiguration + "_" + numNewVictimsPerSnapshot+"_"+starting_snapshot + "_"+ 
                        		num_exe + "_"+ snapShotIndex + ".txt";

                        printGraph(BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph, fName) ;*/


                    	System.out.println("Start the attack ...");
                        num_previousReleases = sequenceGenerator.getSnapshotInformtions().size();
                        long startTime = System.currentTimeMillis();
                        if(snapShotIndex == starting_snapshot)
                        	prob_result= 
                        	attackSimulator.currentSuccessProbability_attack2(BarabasiAlbertSequenceGenerator.getGraph(), 
                        				noisyGraph, BarabasiAlbertSequenceGenerator.getGraph(),
                        				true, false, true);
                        else
                        	prob_result= 
                        		attackSimulator.currentSuccessProbability_attack2(BarabasiAlbertSequenceGenerator.getGraph(), 
                        				noisyGraph, sequenceGenerator.getSnapshotInformtions().get(num_previousReleases-1).getGraph(),
                        				true, false, true);

                        long endTime = System.currentTimeMillis();
                        
                    	System.out.println("attack done ...");
                       
                        double elapsedTime = ((endTime-startTime)/1000d);
                         
                       
                        outputStr = num_exe + " " + snapShotIndex + " " + prob_result.getMatchProb() + " " + 
                        		prob_result.getMaxProb() + " " + prob_result.getSumProb() + 
                        		" " + attackSimulator.victimList.size() + " " + 
                        		attackSimulator.attackerCount + " " + elapsedTime+ " " +  graphStats + "\n";
                        

                        fw.write(outputStr); 
                       
                        fw.flush();
                        break;
                    case 2://consistency, random flip, random add
                    	if(snapShotIndex <= starting_snapshot) {
                    		snapshotInfo2add = new SnapshotInformation(BarabasiAlbertSequenceGenerator.getGraph(),noisyGraph, null,null,null);
                    	}else
                    		snapshotInfo2add = attackSimulator.snapshotInformation;
                    	

                    	//attackSimulator.graphEvolveByRemoval(percentageOfRemoval, sequenceGenerator);

                        sequenceGenerator.makeSnapshotByEdgePercentage(percentageOfAdditions, 
                        		snapshotInfo2add);                        

                        if(snapShotIndex==starting_snapshot) {
                    		attackSimulator.createInitialAttackerSubgraph(initialVictimCount);
                    	}
                        
                        if (snapShotIndex>starting_snapshot){
                    		attackSimulator.addVictims(num_victims);
                    		attackSimulator.evolveAttackerSubgraph(0, 0, 4);
                    	}

                        noisyGraph = sequenceGenerator.getNoisyGraph(percentageOfNoise, 
                        		BarabasiAlbertSequenceGenerator.getGraph());
                        if(snapShotIndex <starting_snapshot)
                        	break;

                        //re-identification refinement
                        if(snapShotIndex> starting_snapshot) {
                        	System.out.println("Refining re-identification ...");
                        	SnapshotInformation snapInfo = attackSimulator.snapshotInformation;	
                        	prob_result = attackSimulator.refineReIdentification(snapInfo.getGraph(), 
                        			snapInfo.getNoisyGraph(), snapInfo.getVictimList(), snapInfo.getSybilList(),snapInfo.getCandidateAttackersList());
                        	outputStr = num_exe + " " + (snapShotIndex-1) + " " + prob_result.getMatchProb() + " " + 
                        		prob_result.getMaxProb() + " " + prob_result.getSumProb()+"\n";
                        	fw.write(outputStr);
                        	fw.flush();
                        }
                        graphStats = calculateGraphStatistics(BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph);
                        
                        /*fName = "Graph_" + finalNodes + "_"+ edgesPerNode +"_" 
                        		+ percentageOfNoise +"_" +initialVictimCount +
                        		"_" + percentageOfAdditions+ "_" + 
                        		attackConfiguration + "_" +  numNewVictimsPerSnapshot+"_"+starting_snapshot + "_"+ num_exe + "_"+ snapShotIndex  + ".txt";

                        printGraph(BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph, fName) ;
                        */


                        num_previousReleases = sequenceGenerator.getSnapshotInformtions().size();

                        startTime = System.currentTimeMillis();
                        if(snapShotIndex == starting_snapshot)
                        	prob_result = attackSimulator.currentSuccessProbability_attack2(BarabasiAlbertSequenceGenerator.getGraph(), 
                        				noisyGraph, BarabasiAlbertSequenceGenerator.getGraph(),
                        				true, true, true);
                        else
                        	prob_result= 
                        	attackSimulator.currentSuccessProbability_attack2(BarabasiAlbertSequenceGenerator.getGraph(), 
                        				noisyGraph, sequenceGenerator.getSnapshotInformtions().get(num_previousReleases-1).getGraph(),
                        				true, true, true);
                       
                        endTime = System.currentTimeMillis();
                        elapsedTime = ((endTime - startTime)/1000d);
                        outputStr = num_exe + " " + snapShotIndex + " " + prob_result.getMatchProb() + " " + 
                        		prob_result.getMaxProb() + " " + prob_result.getSumProb() + 
                        		" " + attackSimulator.victimList.size() + " " + 
                        		attackSimulator.attackerCount + " " + elapsedTime + " " + graphStats + "\n";
                        

                        fw.write(outputStr); 
                        
                        fw.flush();
                        break;
                 }
            	}
            }

        }
        fw.close();
    }
    public String calculateGraphStatistics(SimpleGraph<String, DefaultEdge> originalGraph, 
    		SimpleGraph<String, DefaultEdge> noisyGraph) {

    	//number of nodes and number of edges
    	StringBuffer bf = new StringBuffer();
    	bf.append(originalGraph.vertexSet().size()+" "+ noisyGraph.vertexSet().size()+ " "
    			+originalGraph.edgeSet().size() + " " + noisyGraph.edgeSet().size() + " ");
    	//number of flips
    	bf.append(GraphStatisiticsGenerator.countEdgeFlips(originalGraph, noisyGraph) + " ");
    	
    	bf.append(GraphStatisiticsGenerator.avgLocalClusteringCoefficient(originalGraph) + 
    			" " + GraphStatisiticsGenerator.avgLocalClusteringCoefficient(noisyGraph)+" ");
//    	bf.append(GraphStatisiticsGenerator.globalClusteringCoefficient(originalGraph) + " "+
//    			GraphStatisiticsGenerator.globalClusteringCoefficient(noisyGraph)+" ");
//    	bf.append(GraphStatisiticsGenerator.cosineSortedDegreeDistributions(originalGraph, noisyGraph)
 //   			+" " +GraphStatisiticsGenerator.cosineUnsortedDegreeDistributions(originalGraph, noisyGraph) + " ");
    	bf.append(GraphStatisiticsGenerator.klDivergenceDegreeDistributions(originalGraph, noisyGraph));
    	return bf.toString();
    	
    }
    public void printGraph(SimpleGraph<String, DefaultEdge> graph, String outputFile) throws IOException {
		FileWriter fout = new FileWriter(outputFile);
		for (DefaultEdge e : graph.edgeSet()) {
			String vs = graph.getEdgeSource(e);
			String vt = graph.getEdgeTarget(e);
			fout.write(vs + " " + vt + "\n");
		}
		fout.close();
	}

    public void printGraph(SimpleGraph<String, DefaultEdge> originGraph, 
    		SimpleGraph<String, DefaultEdge> noisyGraph,String outputFile) throws IOException {
    	String originalGraphFileName = "OriginalGraphs/" + File.pathSeparator + outputFile; 
    	String noisyGraphFileName = "NoisyGraphs/"  + outputFile; 
    	this.printGraph(originGraph, originalGraphFileName);
    	this.printGraph(noisyGraph, noisyGraphFileName);
    }
 public void executeExperimentRGMathoverflowInteractionGraph(int initialVictimCount, double percentageOfNoise, 
			int numNewVictimsPerSnapshot, String nodeMappingFile, int starting_snapshot)
			throws IOException {

		String graphStats = "";
		// Keep in mind that 'snapshotsPerGraph' should be divisible by
		// 'frequencyOfAverage'

		String fileName = "results/MOF_" + percentageOfNoise + "_" + initialVictimCount
				+ "_" + "1" + "_" + starting_snapshot + ".txt";
		FileWriter fw = new FileWriter(fileName, true);

		int num_victims = numNewVictimsPerSnapshot;
		for (int num_exe = 1; num_exe <= 100; num_exe++) {
			BarabasiAlbertSequenceGenerator<String, DefaultEdge> sequenceGenerator = new BarabasiAlbertSequenceGenerator<>();

			// the parameter 1 does not have any meaning
			int num_snapshots = sequenceGenerator.initializeRealGraph(nodeMappingFile, null, "mathoverflow");
			SimpleGraph<String, DefaultEdge> noisyGraph = null;

			sybilAttackDynamicSimulator attackSimulator = new sybilAttackDynamicSimulator();

			probResult prob_result;

			for (int snapShotIndex = 0; snapShotIndex < num_snapshots; snapShotIndex++) {

				System.out.println("Start attacking the snapshot " + snapShotIndex + "...");
				if (snapShotIndex == 0) {
					noisyGraph = sequenceGenerator.getNoisyGraphMathoverflow(percentageOfNoise,
							BarabasiAlbertSequenceGenerator.getGraph());
				} else {
					int num_previousReleases;
					String outputStr;
					String fName;
					SnapshotInformation snapshotInfo2add;
					if (snapShotIndex <= starting_snapshot) {
							snapshotInfo2add = new SnapshotInformation(BarabasiAlbertSequenceGenerator.getGraph(), 
									noisyGraph, null,null, null);
					} else
						snapshotInfo2add = attackSimulator.snapshotInformation;

						// attackSimulator.graphEvolveByRemoval(percentageOfRemoval, sequenceGenerator);

					sequenceGenerator.makeSnapshotMathoverflow(nodeMappingFile, snapshotInfo2add);

					if (snapShotIndex == starting_snapshot)
							attackSimulator.createInitialAttackerSubgraph(initialVictimCount);
					else if (snapShotIndex > starting_snapshot) {
							// attackSimulator.evolveAttackerSubgraph(0, 0, 2);
							attackSimulator.addVictims(num_victims);
							attackSimulator.evolveAttackerSubgraph(0, 0, 4);

					}

					noisyGraph = sequenceGenerator.getNoisyGraphMathoverflow(percentageOfNoise,
								BarabasiAlbertSequenceGenerator.getGraph());

					if (snapShotIndex < starting_snapshot)
							continue;

					if(snapShotIndex> starting_snapshot) {
                        System.out.println("Refining re-identification ...");
                        SnapshotInformation snapInfo = attackSimulator.snapshotInformation;	
                        prob_result = attackSimulator.refineReIdentification(snapInfo.getGraph(), 
                        			snapInfo.getNoisyGraph(), snapInfo.getVictimList(), snapInfo.getSybilList(),snapInfo.getCandidateAttackersList());
                        outputStr = num_exe + " " + (snapShotIndex-1) + " " + prob_result.getMatchProb() + " " + 
                        		prob_result.getMaxProb() + " " + prob_result.getSumProb()+"\n";
                        fw.write(outputStr);
                        fw.flush();
                    }
						//graphStats = calculateGraphStatistics(BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph);

						/*fName = "RealGraph_" + num_exe + "_" + percentageOfNoise + "_"
								+ initialVictimCount + "_" + attackConfiguration + "_"
								+ starting_snapshot + "_" + snapShotIndex + ".txt";

						printGraph(BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph, fName);
						*/

					num_previousReleases = sequenceGenerator.getSnapshotInformtions().size();
					long startTime = System.currentTimeMillis();
					if (snapShotIndex == starting_snapshot)
						prob_result = attackSimulator.currentSuccessProbability_attack2(
									BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph,
									BarabasiAlbertSequenceGenerator.getGraph(), true, true, true);
					else
						prob_result = attackSimulator.currentSuccessProbability_attack2(
									BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph,
									sequenceGenerator.getSnapshotInformtions().get(num_previousReleases - 1).getGraph(),
									true, true, true);

					long endTime = System.currentTimeMillis();
					double elapsedTime = ((endTime - startTime) / 1000d);
					outputStr = num_exe+" " +snapShotIndex + " " + prob_result.getMatchProb() + " " + prob_result.getMaxProb()
								+ " " + prob_result.getSumProb() + " " + attackSimulator.victimList.size() + " "
								+ attackSimulator.attackerCount + " " + elapsedTime + " " + graphStats + "\n";

					fw.write(outputStr);

					fw.flush();
				}
			}
		}
		fw.close();
	}   
public void executeExperimentRGMathoverflow(int initialVictimCount, double percentageOfNoise, 
			int numNewVictimsPerSnapshot, String nodeMappingFile, String graphFile, int starting_snapshot)
			throws IOException {

		String graphStats = "";
		// Keep in mind that 'snapshotsPerGraph' should be divisible by
		// 'frequencyOfAverage'

		String fileName = "results/MOF_" + percentageOfNoise + "_" + initialVictimCount
				+ "_" + "1" + "_" + starting_snapshot + ".txt";
		FileWriter fw = new FileWriter(fileName, true);

		int num_victims = numNewVictimsPerSnapshot;

		for (int num_exe = 1; num_exe <= 100; num_exe++) {
			BarabasiAlbertSequenceGenerator<String, DefaultEdge> sequenceGenerator = new BarabasiAlbertSequenceGenerator<>();

			// the parameter 1 does not have any meaning
			int num_snapshots = sequenceGenerator.initializeRealGraph(nodeMappingFile, graphFile, "mathoverflow");
			SimpleGraph<String, DefaultEdge> noisyGraph = null;

			sybilAttackDynamicSimulator attackSimulator = new sybilAttackDynamicSimulator();

			probResult prob_result;

			for (int snapShotIndex = 0; snapShotIndex < num_snapshots; snapShotIndex++) {

				System.out.println("Start attacking the snapshot " + snapShotIndex + "...");
				if (snapShotIndex == 0) {
					noisyGraph = sequenceGenerator.getNoisyGraph(percentageOfNoise,
							BarabasiAlbertSequenceGenerator.getGraph());
				} else {
					int num_previousReleases;
					String outputStr;
					String fName;
					SnapshotInformation snapshotInfo2add;
					if (snapShotIndex <= starting_snapshot) {
							snapshotInfo2add = new SnapshotInformation(BarabasiAlbertSequenceGenerator.getGraph(), 
									noisyGraph, null,null, null);
					} else
						snapshotInfo2add = attackSimulator.snapshotInformation;

						// attackSimulator.graphEvolveByRemoval(percentageOfRemoval, sequenceGenerator);

					sequenceGenerator.makeSnapshotMathflow(nodeMappingFile, graphFile, snapshotInfo2add);

					if (snapShotIndex == starting_snapshot)
							attackSimulator.createInitialAttackerSubgraph(initialVictimCount);
					else if (snapShotIndex > starting_snapshot) {
							// attackSimulator.evolveAttackerSubgraph(0, 0, 2);
							attackSimulator.addVictims(num_victims);
							attackSimulator.evolveAttackerSubgraph(0, 0, 4);

					}

					noisyGraph = sequenceGenerator.getNoisyGraph(percentageOfNoise,
								BarabasiAlbertSequenceGenerator.getGraph());

					if (snapShotIndex < starting_snapshot)
							continue;

				/*	if(snapShotIndex> starting_snapshot) {
                        System.out.println("Refining re-identification ...");
                        SnapshotInformation snapInfo = attackSimulator.snapshotInformation;	
                        prob_result = attackSimulator.refineReIdentification(snapInfo.getGraph(), 
                        			snapInfo.getNoisyGraph(), snapInfo.getVictimList(), snapInfo.getSybilList(),snapInfo.getCandidateAttackersList());
                        outputStr = num_exe + " " + (snapShotIndex-1) + " " + prob_result.getMatchProb() + " " + 
                        		prob_result.getMaxProb() + " " + prob_result.getSumProb()+"\n";
                        fw.write(outputStr);
                        fw.flush();
                    }
                  */
						graphStats = calculateGraphStatistics(BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph);

						/*fName = "RealGraph_" + num_exe + "_" + percentageOfNoise + "_"
								+ initialVictimCount + "_" + attackConfiguration + "_"
								+ starting_snapshot + "_" + snapShotIndex + ".txt";

						printGraph(BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph, fName);
						*/

					num_previousReleases = sequenceGenerator.getSnapshotInformtions().size();
					long startTime = System.currentTimeMillis();
					if (snapShotIndex == starting_snapshot)
						prob_result = attackSimulator.currentSuccessProbability_attack2(
									BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph,
									BarabasiAlbertSequenceGenerator.getGraph(), true, true, true);
					else
						prob_result = attackSimulator.currentSuccessProbability_attack2(
									BarabasiAlbertSequenceGenerator.getGraph(), noisyGraph,
									sequenceGenerator.getSnapshotInformtions().get(num_previousReleases - 1).getGraph(),
									true, true, true);

					long endTime = System.currentTimeMillis();
					double elapsedTime = ((endTime - startTime) / 1000d);
					outputStr = num_exe+" " +snapShotIndex + " " + prob_result.getMatchProb() + " " + prob_result.getMaxProb()
								+ " " + prob_result.getSumProb() + " " + attackSimulator.victimList.size() + " "
								+ attackSimulator.attackerCount + " " + elapsedTime + " " + graphStats + "\n";

					fw.write(outputStr);

					fw.flush();
				}
			}
		}
		fw.close();
	} 
}