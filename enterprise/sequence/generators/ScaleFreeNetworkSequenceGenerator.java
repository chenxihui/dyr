/**
 * In an initial implementation, whenever the initialization of the generator is needed, we have two options. One, when initializing the generator
 * and we want to add vertices in sequential manner we use the constructor with 0 parameters.
 * On the other side, when we want to initialize a sequence generator with the growth of the number of edges we use 
 * the constructor with one parameter(edgeCount).
 * Keep in mind that you can work only with one kind of generator.
 * */
package enterprise.sequence.generators;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.function.Supplier;

import org.jgrapht.*;
import org.jgrapht.generate.ScaleFreeGraphGenerator;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;
import org.jgrapht.io.DOTExporter;
import org.jgrapht.io.ExportException;
import org.jgrapht.io.GraphExporter;
import org.jgrapht.io.GraphMLExporter;
import org.jgrapht.util.SupplierUtil;

import com.google.common.graph.Graphs;

import generators.jgrapht.ScaleFreeGraphGeneratorMe;

public class ScaleFreeNetworkSequenceGenerator<V, E> implements PeriodicallyPublishableDynamicGraph<V, E>{
	
	//private int numberOfModificatoins;
	public static int NUMBER_OF_GENERATIONS = 1;
	
	protected boolean takeSnapshotsByEdgeAdditions;
	protected int edgesPerSnapshot;
	
	private SimpleGraph<String, DefaultEdge> graph;
	private ArrayList<String> vertexList;
	
	Controller controller = new Controller();
	ArrayList<Graph<String, DefaultEdge>> snapshotList = controller.getSnapshotList();
	ArrayList<Integer> graphSizes = new ArrayList<Integer>();
	
	private int EDGE_COUNT = 0;
	
	Supplier<String> vSupplier = new Supplier<String>() {
        private int id = 0;

        @Override
        public String get()
        {
            return "" + id++;
        }
    };
	
	public ScaleFreeNetworkSequenceGenerator() {
		this.takeSnapshotsByEdgeAdditions = false;
		this.graph = new SimpleGraph<>(vSupplier, SupplierUtil.createDefaultEdgeSupplier(), false);
	}
	
	public ScaleFreeNetworkSequenceGenerator(int edgeCount) {
		this.takeSnapshotsByEdgeAdditions = true;
		this.edgesPerSnapshot = edgeCount;
		this.graph = new SimpleGraph<>(vSupplier, SupplierUtil.createDefaultEdgeSupplier(), false);
	}
	
	private final Random random = new Random();
    
	@Override
	public void initialize(int initialNodes) {
		ScaleFreeGraphGeneratorMe<String, DefaultEdge> scaleFreeGraphGenerator = new ScaleFreeGraphGeneratorMe<String, DefaultEdge>(initialNodes);
		scaleFreeGraphGenerator.generateGraph(graph);
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
		if(takeSnapshotsByEdgeAdditions) {			
			if(!snapshotList.isEmpty()) {
				printGraphForRelease(snapshotList.get(0));
				snapshotList.remove(0);
			}else {
				growGraphWithEdges();
				printGraphForRelease(snapshotList.get(0));
				snapshotList.remove(0);
			}
		}else {
			growGraphWithVertex(numberOfModification);
			printGraphForRelease(graph);
		}		
	}
	
	protected int getArraySize() {
		return snapshotList.size();
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
				o = new PrintStream(new File("Generations/ScaleFreeNetwork(Edges)-Snapshot_" + NUMBER_OF_GENERATIONS +".txt"));
			}else {
				o = new PrintStream(new File("Generations/ScaleFreeNetwork(Vertices)-Snapshot_" + NUMBER_OF_GENERATIONS +".txt"));
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
				oGML = new PrintStream(new File("GenerationsGML/ScaleFreeNetwork(Edges)-Snapshot_" + NUMBER_OF_GENERATIONS +".txt"));
			}else {
				oGML = new PrintStream(new File("GenerationsGML/ScaleFreeNetwork(Vertices)-Snapshot_" + NUMBER_OF_GENERATIONS +".txt"));
			}
			
			System.setOut(oGML);
			System.out.println(writergml.toString());
			NUMBER_OF_GENERATIONS++;
			
		} catch (FileNotFoundException ex) {
			// TODO Auto-generated catch block
			ex.printStackTrace();
		}
		
	}
	
	private void growGraphWithVertex(int numberOfModificatoins)
    {
        //List<V> vertexList = new ArrayList<>();
        //List<Integer> degrees = new ArrayList<>();
        //int degreeSum = 0;
        for (int i = 0; i < numberOfModificatoins; i++) {
            String newVertex = graph.addVertex();
            int newDegree = 0;
            while ((newDegree == 0) && (i != 0))
            {
                for (int j = 0; j < vertexList.size(); j++) {
                    if ((ScaleFreeGraphGeneratorMe.DEGREE_SUM == 0) 
                    		|| (random.nextInt(ScaleFreeGraphGeneratorMe.DEGREE_SUM) < ScaleFreeGraphGeneratorMe.DEGREES.get(j))) {
                    	ScaleFreeGraphGeneratorMe.DEGREES.set(j, ScaleFreeGraphGeneratorMe.DEGREES.get(j) + 1);
                        newDegree++;
                        ScaleFreeGraphGeneratorMe.DEGREE_SUM += 2;
                        if (random.nextBoolean()) {
                        	graph.addEdge(vertexList.get(j), newVertex);
                        } else {
                        	graph.addEdge(newVertex, vertexList.get(j));
                        }
                    }
                }
            }
            vertexList.add(newVertex);
            ScaleFreeGraphGeneratorMe.DEGREES.add(newDegree);
        }
        
        //controller.add(graph); 
		controller.add(Utils.cloneGraph(graph));

    }
	
	private void growGraphWithEdges()
    {
        //List<V> vertexList = new ArrayList<>();
        //List<Integer> degrees = new ArrayList<>();
        //int degreeSum = 0;
		
		boolean condition = true;
        while(condition) {
            String newVertex = graph.addVertex();
            int newDegree = 0;
            while ((newDegree == 0))
            {
                for (int j = 0; j < vertexList.size(); j++) {
                    if ((ScaleFreeGraphGeneratorMe.DEGREE_SUM == 0) 
                    		|| (random.nextInt(ScaleFreeGraphGeneratorMe.DEGREE_SUM) < ScaleFreeGraphGeneratorMe.DEGREES.get(j))) {
                    	ScaleFreeGraphGeneratorMe.DEGREES.set(j, ScaleFreeGraphGeneratorMe.DEGREES.get(j) + 1);
                        newDegree++;
                        ScaleFreeGraphGeneratorMe.DEGREE_SUM += 2;
                        if (random.nextBoolean()) {
                        	graph.addEdge(vertexList.get(j), newVertex);
                        	
                        	if (graph.edgeSet().size() == EDGE_COUNT+this.edgesPerSnapshot) {
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
                        	
                        	if(j == vertexList.size() - 1) {
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
                        	
                        } else {
                        	graph.addEdge(newVertex, vertexList.get(j));
                        	
                        	if (graph.edgeSet().size() == EDGE_COUNT+this.edgesPerSnapshot) {
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
                        	
                        	if(j == vertexList.size() - 1) {
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
                        }
                    }
                }
            }
            vertexList.add(newVertex);
            ScaleFreeGraphGeneratorMe.DEGREES.add(newDegree);
        }
        int aaa = 2;
		aaa=2+1;
    }
	//Implementing addEdges is the same method that grows the graph but it is needed for sequential graphs.
	
	private void addEdges(int additions) {
		boolean condition = true;
		outerWhile:
        while(condition) {
            String newVertex = graph.addVertex();
            int newDegree = 0;
            while ((newDegree == 0))
            {
                for (int j = 0; j < vertexList.size(); j++) {
                    if ((ScaleFreeGraphGeneratorMe.DEGREE_SUM == 0) 
                    		|| (random.nextInt(ScaleFreeGraphGeneratorMe.DEGREE_SUM) < ScaleFreeGraphGeneratorMe.DEGREES.get(j))) {
                    	ScaleFreeGraphGeneratorMe.DEGREES.set(j, ScaleFreeGraphGeneratorMe.DEGREES.get(j) + 1);
                        newDegree++;
                        ScaleFreeGraphGeneratorMe.DEGREE_SUM += 2;
                        if (random.nextBoolean()) {
                        	graph.addEdge(vertexList.get(j), newVertex);
                        	if (graph.edgeSet().size() == graph.edgeSet().size() + additions) {
                        		condition = false;
                        		break outerWhile;
                        	}
                      
                        	
                        } else {
                        	graph.addEdge(newVertex, vertexList.get(j));
                        }
                    }
                }
            }
            vertexList.add(newVertex);
            ScaleFreeGraphGeneratorMe.DEGREES.add(newDegree);
        }
	}
	
	//cloneGraph method for generic graph class of type <V, E>
	public Graph<V, E> cloneGraph(Graph<V, E> graph) {
		SimpleGraph<V, E> result = new SimpleGraph<V, E>((Class<? extends E>) DefaultEdge.class);
		for (V v : graph.vertexSet()){
			result.addVertex(v);
		}
		for (V v1 : graph.vertexSet()){
			for (V v2 : graph.vertexSet()){
				if (graph.containsEdge(v1, v2))
					result.addEdge(v1, v2);
			}
		}
		return result;
	}
}
