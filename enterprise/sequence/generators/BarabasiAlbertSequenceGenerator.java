/**
 * In an initial implementation, whenever the initialization of the generator is needed, we have two options. One, when initializing the generator
 * and we want to add vertices in sequential manner we use the constructor with three parameters (initialNodes, edgesPerNode, finalNodes).
 * On the other side, when we want to initialize a sequence generator with the growth of the number of edges we use the constructor with four parameters
 * ( initalNodes, edgesPerNode, finalNodeNumber, edgeCount).
 * Keep in mind that you can work only with one kind of generator.
 * */

package enterprise.sequence.generators;

import java.io.BufferedReader;
import java.io.File;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
 
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.jgrapht.Graph;
import org.jgrapht.alg.ConnectivityInspector;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;
import org.jgrapht.io.DOTExporter;
import org.jgrapht.io.ExportException;
import org.jgrapht.io.GraphExporter;
import org.jgrapht.io.GraphMLExporter;
import org.jgrapht.util.SupplierUtil;
import attacks.SnapshotInformation;
import generators.jgrapht.BarabasiAlbertGraphGeneratorMe;
import java.security.SecureRandom;


public class BarabasiAlbertSequenceGenerator<V, E> implements enterprise.sequence.generators.PeriodicallyPublishableDynamicGraph<V, E> {
	
	static class VertexPair implements Comparable<VertexPair> {
		
		public String source, dest;
		
		public VertexPair(String src, String dst) {
			if (src.compareTo(dst) <= 0) {
				source = src;
				dest = dst;
			}
			else {
				source = dst;
				dest = src;
			}
		}

		@Override
		public int compareTo(VertexPair e) {
			if (this.source.compareTo(e.source) == 0)
				return this.dest.compareTo(e.dest);
			else
				return this.source.compareTo(e.source);
		}
		
		public boolean incident(String v) {
			return ((v.equals(source)) || (v.equals(dest)));
		}
		
		@Override
		public String toString() {
			return "(" + source + "," + dest + ")";
		}
		
	}

	public static int NUMBER_OF_GENERATIONS = 1;
	
	protected boolean takeSnapshotsByEdgeAdditions;
	protected int edgesPerSnapshot;
	private int initalNodes;
	private int edgesPerNode;
	private int finalNodeNumber;
	
	public static SimpleGraph<String, DefaultEdge> graph;
	public static HashMap<String, Integer> birthSnapshot = new HashMap<String, Integer>();
	public static HashMap<String, Integer> diedSnapshot = new HashMap<String, Integer>();
	public static int num_snapshots = 0;
	private ArrayList<String> vertexList;
	
	public ArrayList<SnapshotInformation> snapshotInformations = new ArrayList<SnapshotInformation>();
	
	Controller controller = new Controller();
	ArrayList<Graph<String, DefaultEdge>> snapshotList = controller.getSnapshotList();
	ArrayList<Graph<String, DefaultEdge>> allSnapshotsList = controller.getAllGraphs();
	ArrayList<Integer> graphSizes = new ArrayList<Integer>();
	
	List<String> newEndpoints_edgeCreation = new ArrayList<String>();
	
	//Map<String, String> all_noises = new Hashtable<String, String>();
	Multimap<String, String> all_noises = ArrayListMultimap.create();
	
	private int EDGE_COUNT = 0;
	private final Random random;
	private final SecureRandom secureRandom=new SecureRandom();
	
	Supplier<String> vSupplier = new Supplier<String>() {
        private int id = 0;
     	
        @Override
        public String get()
        {
            return ""+ id++;
        }
               
    };
	
	public BarabasiAlbertSequenceGenerator(int initalNodes, int edgesPerNode, int finalNodeNumber) {
		this.takeSnapshotsByEdgeAdditions = false;
		this.initalNodes = initalNodes;
		this.edgesPerNode = edgesPerNode;
		this.finalNodeNumber = finalNodeNumber;
		this.graph = controller.getInitialGraph(); //new SimpleGraph<>(vSupplier, SupplierUtil.createDefaultEdgeSupplier(), false);
		random = new Random();
	}
	public BarabasiAlbertSequenceGenerator() {
		this.takeSnapshotsByEdgeAdditions = false;
		BarabasiAlbertSequenceGenerator.graph = controller.getInitialGraph(); 
		random = new Random();
	}

	public BarabasiAlbertSequenceGenerator(int initalNodes, int edgesPerNode, int finalNodeNumber, 
			int edgeCount) {
		this.takeSnapshotsByEdgeAdditions = true;
		this.edgesPerSnapshot = edgeCount;
		this.initalNodes = initalNodes;
		this.edgesPerNode = edgesPerNode;
		this.finalNodeNumber = finalNodeNumber;
		this.graph = new SimpleGraph<>(vSupplier, SupplierUtil.createDefaultEdgeSupplier(), false);
		random = new Random();
	}
/** In this method whenever we need to initialize the graph we just pass any integer in the method. 
 * Since we are implementing methods from the interface
 * we need to override this as well. **/
	
	@Override
	public void initialize(int initialNodes) {	
		BarabasiAlbertGraphGeneratorMe<String, DefaultEdge> bAFGraphGenerator = 
				new BarabasiAlbertGraphGeneratorMe<String, DefaultEdge>(initalNodes, edgesPerNode, finalNodeNumber);		
		bAFGraphGenerator.generateGraph(graph);
		Set<String> vertexSet = graph.vertexSet();
		this.vertexList = new ArrayList<String>();
		vertexList.addAll(vertexSet);
		EDGE_COUNT = this.graph.edgeSet().size();
		BarabasiAlbertSequenceGenerator.birthSnapshot.clear();
		BarabasiAlbertSequenceGenerator.diedSnapshot.clear();
		for (String v : vertexSet)
			birthSnapshot.put(v, 0);
		BarabasiAlbertSequenceGenerator.num_snapshots = 1;

	}
	public int initializeRealGraph(String nodeMappingFile, String graphFile, String dataName) throws IOException {	
		BarabasiAlbertSequenceGenerator.num_snapshots = 0;

		int total_num_snapshot=0;
		
		if(dataName.contentEquals("petster"))
			total_num_snapshot = this.makeSnapshot(nodeMappingFile, graphFile, 
				new SnapshotInformation(BarabasiAlbertSequenceGenerator.getGraph(),null,null, null,null));
		else if (dataName.contentEquals("mathoverflow"))
			total_num_snapshot=this.makeSnapshotMathflow(nodeMappingFile,graphFile, 
				new SnapshotInformation(BarabasiAlbertSequenceGenerator.getGraph(),null,null, null,null));
			//total_num_snapshot=this.makeSnapshotMathoverflow(nodeMappingFile,
			//	new SnapshotInformation(BarabasiAlbertSequenceGenerator.getGraph(),null,null, null,null));

		Set<String> vertexSet = graph.vertexSet();
		this.vertexList = new ArrayList<String>();
		vertexList.addAll(vertexSet);
		EDGE_COUNT = BarabasiAlbertSequenceGenerator.graph.edgeSet().size();
		BarabasiAlbertSequenceGenerator.birthSnapshot.clear();
		BarabasiAlbertSequenceGenerator.diedSnapshot.clear();
		for (String v : vertexSet)
			birthSnapshot.put(v, 0);
		BarabasiAlbertSequenceGenerator.num_snapshots = 1;

		return total_num_snapshot;
	}
	@Override
	public int getNumberOfModifications(Graph<V, E> graph) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void makeSnapshot(int numberOfModification) {
		// dont use this one
	}

	/** Whenever we call make snapshot we have two cases :
	 * 1- when we grow the graph with vertices we just write the number of additions when calling makeSnapshot(int numberOfModification),
	 * 2- when we grow the graph with edges we have to make sure that we write the same number that we declared in the constructor(edgeCount=numberOfModification). 
	 * **/

	public void makeSnapshot(double percentageOfAdditions, SnapshotInformation snapshotInformation) {

		if(takeSnapshotsByEdgeAdditions) {			
			if(!snapshotList.isEmpty()) {
//				printGraphForRelease(snapshotList.get(0));
				snapshotInformations.add(snapshotInformation);
				snapshotList.remove(0);
			}else {
				growGraphWithEdges();
	//			printGraphForRelease(snapshotList.get(0));
				snapshotInformations.add(snapshotInformation);
				snapshotList.remove(0);
			}
		}else {
			growGraphWithVertex(percentageOfAdditions);
	//		printGraphForRelease(graph);
			snapshotInformations.add(snapshotInformation);
			snapshotList.remove(0);
		}	
	}

	public void makeSnapshotByEdgePercentage(double percentageOfAdditions, SnapshotInformation snapshotInformation) {

			double nodes_percentage= 1.0*(graph.edgeSet().size() * percentageOfAdditions*0.01 /this.edgesPerNode)/graph.vertexSet().size();
			growGraphWithVertex(nodes_percentage);
			growGraphWithVertexWithRemoval(nodes_percentage);
			//printGraphForRelease(graph);
			snapshotInformations.add(snapshotInformation);
			snapshotList.remove(0);
			BarabasiAlbertSequenceGenerator.num_snapshots ++;
	}

	protected void printGraphForRelease(Graph<String, DefaultEdge> graph) {
			//Graph<V, E> graph = snapshotList.get(0);
		GraphExporter<String, DefaultEdge> exporter = new DOTExporter<>();
		
		//GraphExporter<V, E> exporterGraphML=new GraphMLExporter<>();
		Writer writer = new StringWriter();
	    try {
			exporter.exportGraph(graph, writer);
			//exporterGraphML.exportGraph(graph, writer);
		} catch (ExportException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    //System.out.println(writer.toString());
	    PrintStream o;
		try {
			if(takeSnapshotsByEdgeAdditions) {
				o = new PrintStream(new File("Generations/BarabasiAlbert(Edges)-Snapshot_" + NUMBER_OF_GENERATIONS +".txt"));
			}else {
				o = new PrintStream(new File("Generations/BarabasiAlbert(Vertices)-Snapshot_" + NUMBER_OF_GENERATIONS +".txt"));
			}
			
			System.setOut(o);
			System.out.println(writer.toString());
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		/////////////////////////////////////////////////////////////////////////////////////////////
		GraphExporter<String, DefaultEdge> exporterGraphML=new GraphMLExporter<>();

		Writer writergml = new StringWriter();
	    try {
			
			exporterGraphML.exportGraph(graph, writergml);
		} catch (ExportException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    //System.out.println(writer.toString());
	    PrintStream oGML;
		try {
			if(takeSnapshotsByEdgeAdditions) {
				oGML = new PrintStream(new File("GenerationsGML/BarabasiAlbert(Edges)-Snapshot_" + NUMBER_OF_GENERATIONS +".txt"));
			}else {
				oGML = new PrintStream(new File("GenerationsGML/BarabasiAlbert(Vertices)-Snapshot_" + NUMBER_OF_GENERATIONS +".txt"));
			}

			System.setOut(oGML);
			System.out.println(writergml.toString());
			NUMBER_OF_GENERATIONS++;
			
		} catch (FileNotFoundException ex) {
			// TODO Auto-generated catch block
			ex.printStackTrace();
		}
		
	}
	
	public HashMap<String, String> graphEvolveByRemoval(double percentageOfAdditions) {

		int graphVertexSize = graph.vertexSet().size();
		double newAdditionsStaging = (percentageOfAdditions ) * graphVertexSize;
		double newAdditions = (int)newAdditionsStaging;
		
		HashMap<String, Integer> degreeSeq = new HashMap<String,Integer>();

		int maxDegree = 0;
		for (String v: BarabasiAlbertSequenceGenerator.graph.vertexSet()) {
			int degree = BarabasiAlbertSequenceGenerator.graph.edgesOf(v).size();
			degreeSeq.put(v, degree);
			if(degree > maxDegree)
				maxDegree = degree;

		}

		HashMap<String, Integer> sortedMap = degreeSeq.entrySet().stream()
			    .sorted(Entry.comparingByValue())
			    .collect(Collectors.toMap(Entry::getKey, Entry::getValue,
			                              (e1, e2) -> e1, LinkedHashMap::new));

	    int changedNodeNum = (int)(graphVertexSize * 0.8);	
	    ArrayList<String> node2changeList = new ArrayList<String>();
	    Iterator<Entry<String, Integer>> iter = sortedMap.entrySet().iterator();

	    int j = 0; int totalDegree = 0 ; 
	    while(iter.hasNext()) {
	    	Entry<String, Integer>  pair = iter.next();
	    	String key = pair.getKey();
	    	int value = pair.getValue();
	    	if (j < changedNodeNum) {
	    		sortedMap.put(key, maxDegree-value);
	    		totalDegree += (maxDegree- value);
	    		node2changeList.add(key);
	    	}else
	    		sortedMap.put(key, 0);
	    	j ++; 
	    }
		
		//select nodes to remove

		HashMap<String, String> diedNodesMap = new HashMap<String,String>();
		for (int i = 0; i< newAdditions; i++ ) {
			String node = node2changeList.get(new Random().nextInt(changedNodeNum));
			while(diedNodesMap.containsKey(node))
				node = node2changeList.get(new Random().nextInt(changedNodeNum));

            String newNode = graph.addVertex();
            BarabasiAlbertSequenceGenerator.birthSnapshot.put(newNode, BarabasiAlbertSequenceGenerator.num_snapshots);
				
			for(DefaultEdge e : BarabasiAlbertSequenceGenerator.getGraph().edgesOf(node)) {
				String neighbour = BarabasiAlbertSequenceGenerator.graph.getEdgeSource(e);
				if (neighbour.equalsIgnoreCase(node)) 
					neighbour = BarabasiAlbertSequenceGenerator.graph.getEdgeTarget(e);
				BarabasiAlbertSequenceGenerator.getGraph().removeEdge(e);
				BarabasiAlbertSequenceGenerator.getGraph().addEdge(newNode, neighbour);
			}
			BarabasiAlbertSequenceGenerator.getGraph().removeVertex(node);
			BarabasiAlbertSequenceGenerator.birthSnapshot.remove(node);
			BarabasiAlbertSequenceGenerator.diedSnapshot.put(node, BarabasiAlbertSequenceGenerator.num_snapshots);
			diedNodesMap.put(node, newNode);
		}
	   
		return diedNodesMap;
		
	}
	private void growGraphWithVertex(double percentageOfAdditions) {
		Set<String> nodeSet = graph.vertexSet();
        List<String> nodes = new ArrayList<String>();
        for (String node:nodeSet) {
        	for (int i = 0; i < graph.degreeOf(node); i++)
        		nodes.add(node);
        }
		int graphVertexSize = graph.vertexSet().size();
		double newAdditionsStaging = (percentageOfAdditions ) * graphVertexSize;
		double newAdditions = (int)newAdditionsStaging;

		for (int i = 0; i < newAdditions; i++) {
            String v = graph.addVertex();
            BarabasiAlbertSequenceGenerator.birthSnapshot.put(v,BarabasiAlbertSequenceGenerator.num_snapshots);
            List<String> newEndpoints = new ArrayList<>();
            int added = 0;
            while (added < edgesPerNode) {
                String u = nodes.get(random.nextInt(nodes.size()));
                if (!graph.containsEdge(v, u)) {
                	graph.addEdge(v, u);
                    added++;
                    newEndpoints.add(v);
                    if (i > 1) {
                        newEndpoints.add(u);
                    }
                }
            }
            nodes.addAll(newEndpoints);
        }
		controller.add(Utils.cloneGraph(graph));
		//controller.addToAll(Utils.cloneGraph(graph));
    }
	private void growGraphWithVertexWithRemoval(double percentageOfAdditions) {
		double percentOfRemovalBasedOnAddition = 0.2;
		Set<String> nodeSet = graph.vertexSet();
        List<String> nodes = new ArrayList<String>();
        for (String node:nodeSet) {
        	for (int i = 0; i < graph.degreeOf(node); i++)
        		nodes.add(node);
        }
		int graphVertexSize = graph.vertexSet().size();

		double newAdditionsStaging = (percentageOfAdditions ) * graphVertexSize;
		
		int newAdditions = (int)newAdditionsStaging;
		int newRemovals = 
				new Random().nextInt((int)(percentOfRemovalBasedOnAddition*newAdditionsStaging)) ;
		for (int i = 0; i<newRemovals; i++) {
			String u = nodes.get(random.nextInt(nodes.size()));
			
			while(u.substring(0, 1).contentEquals("-")|| !graph.vertexSet().contains(u))
				u = nodes.get(random.nextInt(nodes.size()));

			ArrayList<String> neiList = new ArrayList<String>();
			for (DefaultEdge e : graph.edgesOf(u)) {
				String neighbour= ""; 
				if(graph.getEdgeSource(e).contentEquals(u))
					neighbour=graph.getEdgeTarget(e);
				else
					neighbour = graph.getEdgeSource(e);
				neiList.add(neighbour);
			}

			for(String nei:neiList) {
				graph.removeEdge(u, nei);
			}
			BarabasiAlbertSequenceGenerator.diedSnapshot.put(u, 
					BarabasiAlbertSequenceGenerator.num_snapshots);
	
			graph.removeVertex(u);

		}
		HashMap<String, Double> degreeDist = new HashMap<String, Double>();
		int totalDegree = 2*graph.edgeSet().size();
		for(String node: graph.vertexSet()) {
			degreeDist.put(node, graph.degreeOf(node)*1.0/totalDegree);
		}

		for (int i = 0; i < newAdditions; i++) {
            String v = graph.addVertex();
            BarabasiAlbertSequenceGenerator.birthSnapshot.put(v,BarabasiAlbertSequenceGenerator.num_snapshots);
            List<String> newEndpoints = new ArrayList<>();
            int added = 0;
            while (added < edgesPerNode) {
            	double r = new Random().nextDouble();
            	double sum = 0 ;
            	String u = "";
            	Iterator<String> iter = degreeDist.keySet().iterator();
            	while(iter.hasNext()&& sum<r) {
            		u = iter.next();
            		sum += degreeDist.get(u);
            	}
                //String u = nodes.get(random.nextInt(nodes.size()));
                if (!graph.containsEdge(v, u)) {
                	graph.addEdge(v, u);
                    added++;
                    newEndpoints.add(v);
                    if (i > 1) {
                        newEndpoints.add(u);
                    }
                }
            }
            nodes.addAll(newEndpoints);
        }
		controller.add(Utils.cloneGraph(graph));
		//controller.addToAll(Utils.cloneGraph(graph));
    }
	public int makeSnapshot(String nodeMappingFile, String graphFile, 
			SnapshotInformation snapshotInformation) throws IOException  {
		BufferedReader fMapping = new BufferedReader(new FileReader(nodeMappingFile));
		String line;
		HashMap<String, String> nodeMap = new HashMap<String, String> ();
		int maxSnapshotIndex=0;

		while ((line = fMapping.readLine())!=null) {
			String[] fds = line.split("\t");
			nodeMap.put(fds[1], fds[0]);
			int snapshotIndex = Integer.parseInt(fds[2]);
			
			if (snapshotIndex <= BarabasiAlbertSequenceGenerator.num_snapshots)
				if(!BarabasiAlbertSequenceGenerator.getGraph().containsVertex(fds[0])) {
						BarabasiAlbertSequenceGenerator.getGraph().addVertex(fds[0]);
						BarabasiAlbertSequenceGenerator.birthSnapshot.put(fds[0], 
								BarabasiAlbertSequenceGenerator.num_snapshots);
				}
			if (maxSnapshotIndex <= snapshotIndex)
				maxSnapshotIndex = snapshotIndex;
		}
		
		fMapping.close();

		if(BarabasiAlbertSequenceGenerator.num_snapshots> maxSnapshotIndex)
			return -1;
		else
			BarabasiAlbertSequenceGenerator.num_snapshots++;
		
		BufferedReader fGraph = new BufferedReader(new FileReader(graphFile));
		while((line = fGraph.readLine())!=null) {
			String[] fds = line.split(" ");
			if(BarabasiAlbertSequenceGenerator.getGraph().containsVertex(nodeMap.get(fds[0])) &&
					BarabasiAlbertSequenceGenerator.getGraph().containsVertex(nodeMap.get(fds[1])))
				BarabasiAlbertSequenceGenerator.getGraph().addEdge(
						nodeMap.get(fds[0]), nodeMap.get(fds[1]));
		}
		
		fGraph.close();
		
		snapshotInformations.add(snapshotInformation);

		return maxSnapshotIndex;
	}
	
	public int makeSnapshotMathoverflow(String nodeMappingFile,  
			SnapshotInformation snapshotInformation) throws IOException  {

		String graphFile ="mathflowGraphs/mathoverflow_" + BarabasiAlbertSequenceGenerator.num_snapshots+".txt";

		BufferedReader fMapping = new BufferedReader(new FileReader(nodeMappingFile));
		String line;
		int maxSnapshotIndex=0;
		SimpleGraph<String, DefaultEdge> g = controller.getInitialGraph();

		while ((line = fMapping.readLine())!=null) {
			String[] fds = line.split("\t");
			int snapshotIndex = Integer.parseInt(fds[2]);
			
			if (snapshotIndex == BarabasiAlbertSequenceGenerator.num_snapshots) {
				g.addVertex(fds[0]);
				if(!BarabasiAlbertSequenceGenerator.getGraph().containsVertex(fds[0])) 
					BarabasiAlbertSequenceGenerator.birthSnapshot.put(fds[0], snapshotIndex);
			}
			if (maxSnapshotIndex <= snapshotIndex)
					maxSnapshotIndex = snapshotIndex;
		}
		
		if(BarabasiAlbertSequenceGenerator.num_snapshots> maxSnapshotIndex)
			return -1;
		int num_sybil = 0;
		for(String v: BarabasiAlbertSequenceGenerator.getGraph().vertexSet()) {
			if(v.startsWith("-")) {
				g.addVertex(v);
				num_sybil ++;
			}else if(!g.containsVertex(v))
				BarabasiAlbertSequenceGenerator.diedSnapshot.put(v, BarabasiAlbertSequenceGenerator.num_snapshots);
			
		}
		
		for (int i = -1 * num_sybil; i<0; i++) {
			String v = "" + i;
			for(DefaultEdge e:BarabasiAlbertSequenceGenerator.getGraph().edgesOf(v)) {
					String t = BarabasiAlbertSequenceGenerator.getGraph().getEdgeSource(e).contentEquals(v)?
							BarabasiAlbertSequenceGenerator.getGraph().getEdgeTarget(e):
								BarabasiAlbertSequenceGenerator.getGraph().getEdgeSource(e);
					if( g.containsVertex(t)&& !g.containsEdge(v, t))
						g.addEdge(v, t);
				}
		}
		fMapping.close();

		BufferedReader fGraph = new BufferedReader(new FileReader(graphFile));
		while((line = fGraph.readLine())!=null) {
			String[] fds = line.split(" ");
			if(!g.containsVertex(fds[0])){
				g.addVertex(fds[0]);
				if(!BarabasiAlbertSequenceGenerator.getGraph().containsVertex(fds[0]))
					BarabasiAlbertSequenceGenerator.birthSnapshot.put(fds[0], 
						BarabasiAlbertSequenceGenerator.num_snapshots);
			}
			
			if(!g.containsVertex(fds[1])) {
				g.addVertex(fds[1]);
				if(!BarabasiAlbertSequenceGenerator.getGraph().containsVertex(fds[1]))
					BarabasiAlbertSequenceGenerator.birthSnapshot.put(fds[1], 
						BarabasiAlbertSequenceGenerator.num_snapshots);
			}

			if(!fds[0].contentEquals(fds[1])&& !g.containsEdge(fds[0], fds[1]))
				g.addEdge(fds[0], fds[1]);
		}
		
		fGraph.close();
		
		snapshotInformations.add(snapshotInformation);

		BarabasiAlbertSequenceGenerator.graph = g;
		BarabasiAlbertSequenceGenerator.num_snapshots++;

		return maxSnapshotIndex;
	}

	private void growGraphWithEdges() {
		Set<String> nodeSet = graph.vertexSet();
        List<String> nodes = new ArrayList<String>();
        nodes.addAll(nodeSet);
        EDGE_COUNT =  graph.edgeSet().size();
        
		boolean condition = true;
		while(condition) {			
	        String v = graph.addVertex();
	
	        int added = 0;
	        while (added < edgesPerNode) {
	            String u = nodes.get(random.nextInt(nodes.size()));
	            if (!graph.containsEdge(v, u)) {
	            	graph.addEdge(v, u);
	                added++;
	                newEndpoints_edgeCreation.add(v);
	                if (graph.edgeSet().size() == EDGE_COUNT + this.edgesPerSnapshot) {
	            		controller.add(Utils.cloneGraph(graph));
	            		graphSizes.add((Integer)graph.edgeSet().size());
	            		controller.addToAll(Utils.cloneGraph(graph));
	            		condition = false;
	            	}else if(graph.edgeSet().size() > EDGE_COUNT+this.edgesPerSnapshot) {
						int difference = graph.edgeSet().size() - (EDGE_COUNT + this.edgesPerSnapshot);
						if(difference == this.edgesPerSnapshot) {
							  controller.add(Utils.cloneGraph(graph));
							  graphSizes.add((Integer)graph.edgeSet().size());
							  controller.addToAll(Utils.cloneGraph(graph));
						}else if(difference > this.edgesPerSnapshot){
							  if(difference % this.edgesPerSnapshot == 0) {
								  controller.add(Utils.cloneGraph(graph));
								  graphSizes.add((Integer)graph.edgeSet().size());
								  controller.addToAll(Utils.cloneGraph(graph));
							  }						 
						}else if(difference < this.edgesPerSnapshot) {
							  int additions = this.edgesPerSnapshot - difference; 
							  addEdges(additions); 
							  controller.add(Utils.cloneGraph(graph));
							  graphSizes.add((Integer)graph.edgeSet().size());
							  controller.addToAll(Utils.cloneGraph(graph));
						 }
	            	}
	            }
	        }
	        nodes.addAll(newEndpoints_edgeCreation);	        			
		}		
		int a=0;
		a=+1;
    }
	
	private void addEdges(int additions) {
		Set<String> nodeSet = graph.vertexSet();
		List<String> nodes = new ArrayList<String>();
		nodes.addAll(nodeSet);
		for (int i = 0; i < additions; i++) {
			String v = graph.addVertex();
			String u = nodes.get(random.nextInt(nodes.size()));

			if (!graph.containsEdge(v, u)) {
				graph.addEdge(v, u);
				newEndpoints_edgeCreation.add(v);
			}
		}
	}

	public SimpleGraph<String, DefaultEdge> getNoisyGraph(double percentage, SimpleGraph<String, DefaultEdge> originalGraph)  {
		SimpleGraph<String, DefaultEdge> graph = Utils.cloneGraph(originalGraph);

		//int a1 = graph.vertexSet().size();
		int a1 = graph.edgeSet().size();


		double flips = (percentage/100.0f) * a1;
		
		List<String> vertexList = new ArrayList<>(graph.vertexSet());
		Set<String> keys = all_noises.keySet();
		
		for (String keyprint : keys) {
			if(!graph.containsVertex(keyprint))
				continue;
	        Collection<String> values = all_noises.get(keyprint);

	        for(String value : values){
	        	if(!graph.containsVertex(value))
	        		continue;
	            if (!graph.containsEdge(keyprint, value)) {
					graph.addEdge(keyprint, value);
				}
				else {
					graph.removeEdge(keyprint, value);
				}
	        }
	    }
		
	    int flipaa = (int)flips;
	    Multimap<String, String> new_noises = ArrayListMultimap.create();
	    int tempFlips = 0;
	    while(tempFlips < flipaa) {
	    	String v = vertexList.get(secureRandom.nextInt(vertexList.size()));
	    	String u = vertexList.get(secureRandom.nextInt(vertexList.size()));
	    	VertexPair vp = new VertexPair(v, u);
	    	while (v.equals(u)) {
				v = vertexList.get(random.nextInt(vertexList.size()));
				u = vertexList.get(random.nextInt(vertexList.size()));
				vp = new VertexPair(v, u);
			}
			new_noises.put(v, u);
			all_noises.put(v, u);
			tempFlips++;
	    }
	    
	    Set<String> new_keys = new_noises.keySet();
	    for (String keyprint : new_keys) {
	        Collection<String> values = new_noises.get(keyprint);
	        for(String value : values){
	            if (!graph.containsEdge(keyprint, value)) {
					graph.addEdge(keyprint, value);
					//newEndpoints_edgeCreation.add(key);
				}
				else {
					graph.removeEdge(keyprint, value);
				}
	        }
	    }
	    
		ConnectivityInspector<String, DefaultEdge> inspector= new ConnectivityInspector<String, DefaultEdge>(graph);
		//if(inspector.isGraphConnected()) {
			return graph;
	//	}
	//	else {
	//		return getNoisyGraph(percentage, originalGraph);
	//	}
	}
	
	public static SimpleGraph<String, DefaultEdge> getGraph(){
		return graph;
	}
	
	public ArrayList<SnapshotInformation> getSnapshotInformtions(){
		return this.snapshotInformations;
	}
	
	public static SimpleGraph<String, DefaultEdge> flipRandomEdges(int flipCount, SimpleGraph<String, DefaultEdge> graph) {
		SecureRandom random = new SecureRandom();
		Set<VertexPair> flippedVertexPairs = new TreeSet<>();
		List<String> vertexList = new ArrayList<>(graph.vertexSet()); 
		for (int i = 0; i < flipCount; i++) {
			String v1 = vertexList.get(random.nextInt(vertexList.size()));
			String v2 = vertexList.get(random.nextInt(vertexList.size()));
			VertexPair vp = new VertexPair(v1, v2);
			while (v1.equals(v2) || flippedVertexPairs.contains(vp)) {
				v1 = vertexList.get(random.nextInt(vertexList.size()));
				v2 = vertexList.get(random.nextInt(vertexList.size()));
				vp = new VertexPair(v1, v2);
			}
			if (graph.containsEdge(v1, v2))
				graph.removeEdge(v1, v2);
			else
				graph.addEdge(v1, v2);
		}
		return graph;
	}
	public static SimpleGraph<String, DefaultEdge> cloneGraph(Graph<String, DefaultEdge> gr){
		SimpleGraph<String, DefaultEdge> g = new SimpleGraph<String, DefaultEdge>(DefaultEdge.class);

		for (String v: gr.vertexSet())
			g.addVertex(v);
		for (DefaultEdge e: gr.edgeSet()) {
			String src = gr.getEdgeSource(e);
			String dest = gr.getEdgeTarget(e);
			
			if(!g.containsEdge(src, dest))
				g.addEdge(src, dest);
		}
		return g;
	}
public SimpleGraph<String, DefaultEdge> getNoisyGraphMathoverflow(double percentage, SimpleGraph<String, DefaultEdge> originalGraph)  {
		SimpleGraph<String, DefaultEdge> graph = Utils.cloneGraph(originalGraph);

		//int a1 = graph.vertexSet().size();
		int a1 = graph.edgeSet().size();


		double flips = (percentage/100.0f) * a1;
		
	    int flipaa = (int)flips;
	    Multimap<String, String> new_noises = ArrayListMultimap.create();
	    int tempFlips = 0;
	    while(tempFlips < flipaa) {
	    	String v = vertexList.get(secureRandom.nextInt(vertexList.size()));
	    	String u = vertexList.get(secureRandom.nextInt(vertexList.size()));
	    	VertexPair vp = new VertexPair(v, u);
	    	while (v.equals(u)) {
				v = vertexList.get(random.nextInt(vertexList.size()));
				u = vertexList.get(random.nextInt(vertexList.size()));
				vp = new VertexPair(v, u);
			}
			new_noises.put(v, u);
			all_noises.put(v, u);
			tempFlips++;
	    }
	    
	    
		ConnectivityInspector<String, DefaultEdge> inspector= new ConnectivityInspector<String, DefaultEdge>(graph);
		//if(inspector.isGraphConnected()) {
			return graph;
	}
	public int makeSnapshotMathflow(String nodeMappingFile, String graphFile, 
			SnapshotInformation snapshotInformation) throws IOException  {
		BufferedReader fMapping = new BufferedReader(new FileReader(nodeMappingFile));
		String line;
		HashMap<String, String> nodeMap = new HashMap<String, String> ();
		int maxSnapshotIndex=0;

		while ((line = fMapping.readLine())!=null) {
			String[] fds = line.split("\t");
			nodeMap.put(fds[1], fds[0]);
			int snapshotIndex = Integer.parseInt(fds[2]);
			
			if (snapshotIndex <= BarabasiAlbertSequenceGenerator.num_snapshots)
				if(!BarabasiAlbertSequenceGenerator.getGraph().containsVertex(fds[0])) {
						BarabasiAlbertSequenceGenerator.getGraph().addVertex(fds[0]);
						BarabasiAlbertSequenceGenerator.birthSnapshot.put(fds[0], 
								BarabasiAlbertSequenceGenerator.num_snapshots);
				}
			if (maxSnapshotIndex <= snapshotIndex)
				maxSnapshotIndex = snapshotIndex;
		}
		
		fMapping.close();

		if(BarabasiAlbertSequenceGenerator.num_snapshots> maxSnapshotIndex)
			return -1;
		else
			BarabasiAlbertSequenceGenerator.num_snapshots++;
		
		BufferedReader fGraph = new BufferedReader(new FileReader(graphFile));
		while((line = fGraph.readLine())!=null) {
			String[] fds = line.split(" ");
			if(Integer.parseInt(fds[2])== BarabasiAlbertSequenceGenerator.num_snapshots-1 &&
					!fds[0].contentEquals(fds[1]))
				BarabasiAlbertSequenceGenerator.getGraph().addEdge(
						fds[0], fds[1]);
		}
		
		fGraph.close();
		
		snapshotInformations.add(snapshotInformation);

		return maxSnapshotIndex;
	}
}
