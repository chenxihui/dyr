package attacks;

import java.sql.Array;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Lists;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;
import com.sun.javafx.util.Utils;



public class Test {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
//		List<String[]> candidates_ = new ArrayList<String[]>();
//		List<String[]> candidates = new ArrayList<String[]>();
//		String[] tes = {"1", "2", "3"};
//		String[] tes2 = {"4", "5", "6"};
//
//		String[] tes3 = {"1", "2", "3"};
//		String[] tes4 = {"5", "5", "6"};
//		candidates_.add(tes3);
//		candidates_.add(tes4);
//
//
//
//		candidates.add(tes);
//		candidates.add(tes2);
//
//		if(Arrays.equals(tes,tes3)) {
//			System.out.println("Test");
//		}

		List<Integer> listWithDuplicates = Lists.newArrayList(1, 1, 2, 2, 3, 3);
		List<Integer> listWithoutDuplicates = listWithDuplicates.stream()
				.distinct()
				.collect(Collectors.toList());
		System.out.print(listWithoutDuplicates);
		
//		//System.out.print(getIntersectedList(candidates_, candidates));
//
//		Map<String, Double> maps = new HashMap<String, Double>();
//		maps.put("5", 1.0);
//	    maps.put("4", 0.19);
//	    maps.put("2", 0.54);
//	    maps.put("1", 0.68);
//	    maps.put("3", 0.31);
//	    maps.put("6", 0.89);
//
//		Double min = Double.MAX_VALUE;
//		String fingerprint = "";
//	    for(String key: maps.keySet()) {
//	        Double tmp = maps.get(key);
//	        if(tmp.compareTo(min) < 0) {
//	        	min = tmp;
//	        	fingerprint = key;
//	        }
//	    }
//
//	    System.out.println("FINGERPRINT: " + fingerprint);
//
//	    Map<String, String> mapsTest = new Hashtable<String, String>();
//	    mapsTest.put("5", "4");
//	    mapsTest.put("4", "2");
//	    mapsTest.put("2", "6");
//	    mapsTest.put("1", "2");
//	    mapsTest.put("3", "9");
//	    mapsTest.put("6", "8");
//	    mapsTest.put("9", "3");
//
//	    Multimap<String, String> multiMap = ArrayListMultimap.create();
//	    multiMap.put("AA", "firstValue");
//	    multiMap.put("AA", "secondValue");
//	    multiMap.put("AB", "firstValue");
//	    multiMap.put("AB", "secondValue");
//	    Set<String> keyss = multiMap.keySet();
//	    for (String keyprint : keyss) {
//	        //System.out.println("Key = " + keyprint);
//	        Collection<String> values = multiMap.get(keyprint);
//	        for(String value : values){
//	            System.out.println(keyprint + " = "+ value);
//	        }
//	    }
//
//	    Set<String> keys = mapsTest.keySet();
//	    Iterator<String> itr = keys.iterator();
//	    String str;
//	    while (itr.hasNext()) {
//	        // Getting Key
//	        str = itr.next();
//
//	        /* public V get(Object key): Returns the value to which
//	         * the specified key is mapped, or null if this map
//	         * contains no mapping for the key.
//	         */
//	        System.out.println(str + " " +mapsTest.get(str));
//	     }
//
//
	}
	
	public static List<String[]> getIntersectedList(List<String[]> original, List<String[]> current_new){


		List<String[]> intersections = new ArrayList<String[]>();		
		for(String[] strings: original) {
			for(String[] strings2: current_new) {
				if(Arrays.equals(strings, strings2)) {
					intersections.add(strings);
				}
			}
		}
		if(original.isEmpty()) {
			return current_new;
		}else {
			return intersections;
		}
	}
	
	
	

}
