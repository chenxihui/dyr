package enterprise.sequence.generators;

import java.util.ArrayList;
import java.util.function.Supplier;

import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;
import org.jgrapht.util.SupplierUtil;

public class Controller {

	protected ArrayList<Graph<String, DefaultEdge>> snapshotList = new ArrayList<Graph<String, DefaultEdge>>();
	protected ArrayList<Graph<String, DefaultEdge>> allGraphs = new ArrayList<Graph<String, DefaultEdge>>();
	
	public SimpleGraph<String, DefaultEdge> graph;
	
	Supplier<String> vSupplier = new Supplier<String>() {
        private int id = 0;

     	
        @Override
        public String get()
        {
            return "" + id++;
        }
               
    };
    
	
	public Controller(){
	}
	
	public void add(Graph<String, DefaultEdge> graph) {
		snapshotList.add(graph);
	}
	
	public ArrayList<Graph<String, DefaultEdge>> getSnapshotList(){
		return snapshotList;
	}
	
	public void addToAll(Graph<String, DefaultEdge> graph) {
		allGraphs.add(graph);
	}
	
	public ArrayList<Graph<String, DefaultEdge>> getAllGraphs(){
		return allGraphs;
	}
	
	public SimpleGraph<String, DefaultEdge> getInitialGraph(){
		return graph = new SimpleGraph<>(vSupplier, SupplierUtil.createDefaultEdgeSupplier(), false);
	}
}
