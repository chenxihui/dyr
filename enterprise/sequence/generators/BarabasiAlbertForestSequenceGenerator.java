/**
 * In an initial implementation, whenever the initialization of the generator is needed, we have two options. One, when initializing the generator
 * and we want to add vertices in sequential manner we use the constructor with two parameters (numberOfTrees, finalNodes).
 * On the other side, when we want to initialize a sequence generator with the growth of the number of edges we use the constructor with three parameters
 * ( numberOfTrees, finalNodes, edgeCount).
 * Keep in mind that you can work only with one kind of generator.
 * */

package enterprise.sequence.generators;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.function.Supplier;

import org.jgrapht.Graph;
import org.jgrapht.GraphTests;
import org.jgrapht.generate.BarabasiAlbertForestGenerator;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;
import org.jgrapht.io.DOTExporter;
import org.jgrapht.io.ExportException;
import org.jgrapht.io.GraphExporter;
import org.jgrapht.io.GraphMLExporter;
import org.jgrapht.util.SupplierUtil;

import generators.jgrapht.BarabasiAlbertForestGeneratorMe;

public class BarabasiAlbertForestSequenceGenerator<V, E> implements PeriodicallyPublishableDynamicGraph<V, E> {

	public static int NUMBER_OF_GENERATIONS = 1;

	protected boolean takeSnapshotsByEdgeAdditions;
	protected int edgesPerSnapshot;

	private int numberOftrees;
	private int finalNoNodes;

	public static SimpleGraph<String, DefaultEdge> graph;
	private ArrayList<String> vertexList;

	Controller controller = new Controller();
	ArrayList<Graph<String, DefaultEdge>> snapshotList = controller.getSnapshotList();
	ArrayList<Integer> graphSizes = new ArrayList<Integer>();

	private int EDGE_COUNT = 0;
	private final Random random;

	Supplier<String> vSupplier = new Supplier<String>() {
		private int id = 0;

		@Override
		public String get() {
			return "" + id++;
		}
	};

	public BarabasiAlbertForestSequenceGenerator(int numberOftrees, int finalNoNodes) {
		this.takeSnapshotsByEdgeAdditions = false;
		this.numberOftrees = numberOftrees;
		this.finalNoNodes = finalNoNodes;
		this.graph = new SimpleGraph<>(vSupplier, SupplierUtil.createDefaultEdgeSupplier(), false);
		random = new Random();
	}

	public BarabasiAlbertForestSequenceGenerator(int numberOftrees, int finalNoNodes, int edgeCount) {
		this.takeSnapshotsByEdgeAdditions = true;
		this.edgesPerSnapshot = edgeCount;
		this.numberOftrees = numberOftrees;
		this.finalNoNodes = finalNoNodes;
		this.graph = new SimpleGraph<>(vSupplier, SupplierUtil.createDefaultEdgeSupplier(), false);
		random = new Random();
	}
	
	/** The parameter in this method is not used, because the generator immediately defines the graph. This method initializes the graph.**/
	@Override
	public void initialize(int initialNodes) {
		BarabasiAlbertForestGeneratorMe<String, DefaultEdge> bAFGraphGenerator = new BarabasiAlbertForestGeneratorMe<String, DefaultEdge>(
				numberOftrees, finalNoNodes);
		bAFGraphGenerator.generateGraph(graph);
		Set<String> vertexSet = graph.vertexSet();
		this.vertexList = new ArrayList<String>();
		vertexList.addAll(vertexSet);
		EDGE_COUNT = this.graph.edgeSet().size();
	}

	@Override
	public int getNumberOfModifications(Graph<V, E> graph) {
		// TODO Auto-generated method stub
		return 0;
	}
	
/** Whenever we call makeSnapshot we have two cases :
 * 1- when we grow the graph with vertices we just write the number of additions when calling makeSnapshot(numberOfModification),
 * 2- when we grow the graph with edges we have to make sure that we write the same number that we declared in the constructor(edgeCount=numberOfModification). 
 **/
	
	
	@Override
	public void makeSnapshot(int numberOfModification) {
		if (takeSnapshotsByEdgeAdditions) {
			if (!snapshotList.isEmpty()) {
				printGraphForRelease(snapshotList.get(0));
				snapshotList.remove(0);
			} else {
				growGraphWithEdges();
				printGraphForRelease(snapshotList.get(0));
				snapshotList.remove(0);
			}
		} else {
			growGraphWithVertex(numberOfModification);
			printGraphForRelease(graph);
		}
	}

	protected void printGraphForRelease(Graph<String, DefaultEdge> graph) {
		// Graph<V, E> graph = snapshotList.get(0);
		GraphExporter<String, DefaultEdge> exporter = new DOTExporter<>();

		// GraphExporter<V, E> exporterGraphML=new GraphMLExporter<>();
		Writer writer = new StringWriter();
		try {
			exporter.exportGraph(graph, writer);
			// exporterGraphML.exportGraph(graph, writer);
		} catch (ExportException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// System.out.println(writer.toString());
		PrintStream o;
		try {
			if (takeSnapshotsByEdgeAdditions) {
				o = new PrintStream(
						new File("Generations/BarabasiAlbertForest(Edges)-Snapshot_" + NUMBER_OF_GENERATIONS + ".txt"));
			} else {
				o = new PrintStream(new File(
						"Generations/BarabasiAlbertForest(Vertices)-Snapshot_" + NUMBER_OF_GENERATIONS + ".txt"));
			}

			System.setOut(o);
			System.out.println(writer.toString());
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		/////////////////////////////////////////////////////////////////////////////////////////////
		GraphExporter<String, DefaultEdge> exporterGraphML = new GraphMLExporter<>();

		Writer writergml = new StringWriter();
		try {

			exporterGraphML.exportGraph(graph, writergml);
		} catch (ExportException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// System.out.println(writer.toString());
		PrintStream oGML;
		try {
			if (takeSnapshotsByEdgeAdditions) {
				oGML = new PrintStream(new File(
						"GenerationsGML/BarabasiAlbertForest(Edges)-Snapshot_" + NUMBER_OF_GENERATIONS + ".txt"));
			} else {
				oGML = new PrintStream(new File(
						"GenerationsGML/BarabasiAlbertForest(Vertices)-Snapshot_" + NUMBER_OF_GENERATIONS + ".txt"));
			}

			System.setOut(oGML);
			System.out.println(writergml.toString());
			NUMBER_OF_GENERATIONS++;

		} catch (FileNotFoundException ex) {
			// TODO Auto-generated catch block
			ex.printStackTrace();
		}

	}

	private void growGraphWithVertex(int numberOfModification) {
		GraphTests.requireUndirected(graph);

		assert graph.vertexSet().isEmpty();
		assert graph.edgeSet().isEmpty();

		Set<String> nodeSet = graph.vertexSet();
		List<String> nodes = new ArrayList<String>();
		nodes.addAll(nodeSet);

		/*
		 * Add t roots, one for each tree in the forest
		 */
//        for (int i = 0; i < numberOftrees; i++) {
//            nodes.add(graph.addVertex());
//        }

		/*
		 * Grow forest with preferential attachment
		 */
		// change i from numberOftree to 0
		for (int i = 0; i < numberOfModification; i++) {
			String v = graph.addVertex();
			String u = nodes.get(random.nextInt(nodes.size()));

			if (!graph.containsEdge(v, u)) {
				graph.addEdge(v, u);
			}

			nodes.add(v);

			if (i > 1) {
				nodes.add(u);
			}
		}
	}

	private void growGraphWithEdges() {
		GraphTests.requireUndirected(graph);

		assert graph.vertexSet().isEmpty();
		assert graph.edgeSet().isEmpty();

		Set<String> nodeSet = graph.vertexSet();
		List<String> nodes = new ArrayList<String>();
		nodes.addAll(nodeSet);

		/*
		 * Add t roots, one for each tree in the forest
		 */
//        for (int i = 0; i < numberOftrees; i++) {
//            nodes.add(graph.addVertex());
//        }

		/*
		 * Grow forest with preferential attachment
		 */
		boolean condition = true;
		while (condition) {
			for (int i = numberOftrees; i < finalNoNodes; i++) {
				String v = graph.addVertex();
				String u = nodes.get(random.nextInt(nodes.size()));

				if (!graph.containsEdge(v, u)) {
					graph.addEdge(v, u);
				}

				if (graph.edgeSet().size() == EDGE_COUNT + this.edgesPerSnapshot) {
					controller.add(Utils.cloneGraph(graph));
					graphSizes.add((Integer)graph.edgeSet().size());
					condition = false;
				}else if(graph.edgeSet().size() > EDGE_COUNT+this.edgesPerSnapshot) {
					int difference = graph.edgeSet().size() - (EDGE_COUNT + this.edgesPerSnapshot);
					if(difference == this.edgesPerSnapshot) {
						  controller.add(Utils.cloneGraph(graph));
						  graphSizes.add((Integer)graph.edgeSet().size());
					}else if(difference > this.edgesPerSnapshot){
						  if(difference % this.edgesPerSnapshot == 0) {
							  controller.add(Utils.cloneGraph(graph));
							  graphSizes.add((Integer)graph.edgeSet().size());
						  }						 
					}
				}

				
				 if(i == finalNoNodes - 1) {
					  if(graph.edgeSet().size() > EDGE_COUNT+this.edgesPerSnapshot) { 
						 int difference = graph.edgeSet().size() - (EDGE_COUNT + this.edgesPerSnapshot); 
						  
						 if(difference == this.edgesPerSnapshot) {
							  controller.add(Utils.cloneGraph(graph));
							  graphSizes.add((Integer)graph.edgeSet().size());
						 }else if(difference > this.edgesPerSnapshot){
							 if(difference % this.edgesPerSnapshot == 0) {
								  controller.add(Utils.cloneGraph(graph));
								  graphSizes.add((Integer)graph.edgeSet().size());
							  } 							 
						 }else if(difference < this.edgesPerSnapshot) {
							  int additions = this.edgesPerSnapshot - difference; 
							  addEdges(additions); 
							  controller.add(Utils.cloneGraph(graph));
							  graphSizes.add((Integer)graph.edgeSet().size());
						 }						  
					  }				  
				  }
				 
				nodes.add(v);

				if (i > 1) {
					nodes.add(u);
				}
			}
		}
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
			}
		}
	}

}
