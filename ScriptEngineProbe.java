import javax.script.*;
public class ScriptEngineProbe {
  public static void main(String[] args) throws Exception {
    ScriptEngine engine = new ScriptEngineManager().getEngineByName("graal.js");
    System.out.println(engine == null ? "ENGINE_NULL" : engine.getFactory().getEngineName());
  }
}
