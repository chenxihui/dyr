package util;

public class EdgeConnectivity {
	 /** 
     * @param args 
     */  
    public static void main(String[] args) {  
        double graph[][]={{0,1,0,1,0,0},  
                  {1,0,1,0,1,0},  
                  {0,1,0,0,0,1},  
                  {1,0,0,0,1,0},  
                  {0,1,0,1,0,1},  
                  {0,0,1,0,1,0}};  
        int graph2[][]={  
                  {0,1,1,1,1,1},  
                  {1,0,1,1,1,1},  
                  {1,1,0,1,1,1},  
                  {1,1,1,0,1,1},  
                  {1,1,1,1,0,1},  
                  {1,1,1,1,1,0}};  
       System.out.println(edgeConnectivity(graph2));  
        //System.out.println(graph2.length);
  
    } 
    /**
     * edge connectivity 
     * @param graph
     * @return
     */
    public static int edgeConnectivity(int graph[][]){
    	int length = graph.length;
    	double graphTemp[][] = new double[length][length] ;
    	for(int i=0;i<length;i++){
    		for(int j=0;j<length;j++){
    			graphTemp[i][j] = graph[i][j];
    		}
    	}
    	return edgeConnectivity(graphTemp);
    }
    /**
     * 
     * @param graph
     * @return
     */ 
    public static int edgeConnectivity(double graph[][])  
    {  
        double min=Double.MAX_VALUE;  
        FordFulkerson fordFulkerson = new FordFulkerson(graph.length);
        for(int i=1;i<graph.length;i++)  
        {  
        	
            double maxflow=fordFulkerson.edmondsKarpMaxFlow(graph, 0, i);  
            if(maxflow<min)  
                min=maxflow;  
        }  
        return (int)min;  
    }  
}
