package enterprise.sequence.generators;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;

public interface PeriodicallyPublishableDynamicGraph<V, E>  {

  public void initialize(int initialNodes);
    
  public int getNumberOfModifications(Graph<V, E> graph);
  
  public void makeSnapshot(int numberOfModification);
}	
