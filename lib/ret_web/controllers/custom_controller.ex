defmodule RetWeb.CustomController do
  use RetWeb, :controller

  def index(conn, _params) do
    seconds = DateTime.now!("Etc/UTC") |> DateTime.to_unix()
    json(conn, %{timestamp: seconds})
  end
end
